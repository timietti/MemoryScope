# backend/core/storage.py
"""
Object storage client wrapping boto3 for MinIO / S3.
Dumps are stored encrypted; presigned URLs for direct browser upload
can be generated as an alternative to proxying through the API.
"""
from __future__ import annotations
import logging
from typing import AsyncGenerator

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from backend.config import settings

logger = logging.getLogger(__name__)


def _get_client():
    return boto3.client(
        "s3",
        endpoint_url=settings.S3_ENDPOINT,
        aws_access_key_id=settings.S3_ACCESS_KEY.get_secret_value(),
        aws_secret_access_key=settings.S3_SECRET_KEY.get_secret_value(),
        config=Config(signature_version="s3v4"),
        use_ssl=settings.S3_USE_SSL,
        verify=False,
    )


def ensure_buckets() -> None:
    """Create required buckets if they don't exist. Call on startup."""
    client = _get_client()
    for bucket in [settings.S3_BUCKET_DUMPS, settings.S3_BUCKET_REPORTS]:
        try:
            client.head_bucket(Bucket=bucket)
        except ClientError:
            client.create_bucket(Bucket=bucket)
            logger.info("Created bucket: %s", bucket)


async def upload_dump_stream(
    stream: AsyncGenerator[bytes, None],
    storage_key: str,
    bucket: str,
) -> None:
    """
    Stream upload from an async generator directly to object storage.
    Uses multipart upload for large files.
    """
    import asyncio
    import io

    client = _get_client()

    # Collect chunks (boto3 is sync; for production use aioboto3)
    buffer = io.BytesIO()
    async for chunk in stream:
        buffer.write(chunk)

    buffer.seek(0)
    client.upload_fileobj(
        buffer,
        bucket,
        storage_key,
    )
    logger.info("Uploaded %s to %s/%s", storage_key, bucket, storage_key)


def download_dump(storage_key: str, local_path: str) -> None:
    """Download a dump from object storage to a local path (used in workers)."""
    client = _get_client()
    client.download_file(settings.S3_BUCKET_DUMPS, storage_key, local_path)
    logger.info("Downloaded %s to %s", storage_key, local_path)


def try_download_file(storage_key: str, local_path: str) -> bool:
    """
    Try to download a file from object storage.
    Returns False (without raising) if the object does not exist.
    """
    client = _get_client()
    try:
        client.download_file(settings.S3_BUCKET_DUMPS, storage_key, local_path)
        logger.info("Downloaded companion %s to %s", storage_key, local_path)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return False
        raise


def upload_bytes_sync(data: bytes, storage_key: str, bucket: str) -> None:
    """Upload raw bytes to object storage (sync helper for API and worker use)."""
    import io
    client = _get_client()
    client.upload_fileobj(io.BytesIO(data), bucket, storage_key)
    logger.info("Uploaded %d bytes to %s/%s", len(data), bucket, storage_key)


def delete_case_files(short_id: str, bucket: str | None = None) -> int:
    """
    Delete every object stored under the cases/{short_id}/ prefix.
    Returns the number of objects deleted.
    """
    if bucket is None:
        bucket = settings.S3_BUCKET_DUMPS
    client = _get_client()
    prefix = f"cases/{short_id}/"
    deleted = 0
    paginator = client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if objects:
            client.delete_objects(Bucket=bucket, Delete={"Objects": objects})
            deleted += len(objects)
            logger.info("Deleted %d object(s) from %s/%s", len(objects), bucket, prefix)
    return deleted


def get_storage_client():
    return _get_client()
