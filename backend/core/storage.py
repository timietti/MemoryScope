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
    Stream upload from an async generator to object storage using S3 multipart
    upload.  Only one 64 MB part is held in memory at a time, so arbitrarily
    large files can be uploaded without OOM.
    """
    import asyncio
    from functools import partial

    PART_SIZE = 64 * 1024 * 1024  # 64 MB — well above the 5 MB S3 minimum

    client = _get_client()
    loop = asyncio.get_running_loop()

    mpu = client.create_multipart_upload(Bucket=bucket, Key=storage_key)
    upload_id = mpu["UploadId"]
    parts: list[dict] = []
    part_number = 1
    buf = bytearray()

    try:
        async for chunk in stream:
            buf.extend(chunk)
            while len(buf) >= PART_SIZE:
                part_data = bytes(buf[:PART_SIZE])
                del buf[:PART_SIZE]
                resp = await loop.run_in_executor(
                    None,
                    partial(
                        client.upload_part,
                        Bucket=bucket,
                        Key=storage_key,
                        UploadId=upload_id,
                        PartNumber=part_number,
                        Body=part_data,
                    ),
                )
                parts.append({"PartNumber": part_number, "ETag": resp["ETag"]})
                part_number += 1

        # Final (possibly partial) part — allowed to be smaller than PART_SIZE
        if buf or not parts:
            resp = await loop.run_in_executor(
                None,
                partial(
                    client.upload_part,
                    Bucket=bucket,
                    Key=storage_key,
                    UploadId=upload_id,
                    PartNumber=part_number,
                    Body=bytes(buf),
                ),
            )
            parts.append({"PartNumber": part_number, "ETag": resp["ETag"]})

        client.complete_multipart_upload(
            Bucket=bucket,
            Key=storage_key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
    except Exception:
        client.abort_multipart_upload(Bucket=bucket, Key=storage_key, UploadId=upload_id)
        raise

    logger.info("Streamed %s to %s (multipart, %d part(s))", storage_key, bucket, len(parts))


def upload_fileobj_multipart(fileobj, storage_key: str, bucket: str) -> None:
    """
    Sync multipart upload from any readable file-like object.
    Reads 64 MB at a time; suitable for very large files (e.g. extracted from
    a ZIP) without loading the entire content into memory.
    Call from an async context via ``loop.run_in_executor``.
    """
    PART_SIZE = 64 * 1024 * 1024

    client = _get_client()

    mpu = client.create_multipart_upload(Bucket=bucket, Key=storage_key)
    upload_id = mpu["UploadId"]
    parts: list[dict] = []
    part_number = 1

    try:
        while True:
            # Fill the buffer to PART_SIZE — zipfile ZipExtFile may return
            # fewer bytes per read() call than requested.
            buf = bytearray()
            remaining = PART_SIZE
            while remaining > 0:
                chunk = fileobj.read(remaining)
                if not chunk:
                    break
                buf.extend(chunk)
                remaining -= len(chunk)

            if not buf:
                break

            resp = client.upload_part(
                Bucket=bucket,
                Key=storage_key,
                UploadId=upload_id,
                PartNumber=part_number,
                Body=bytes(buf),
            )
            parts.append({"PartNumber": part_number, "ETag": resp["ETag"]})
            part_number += 1

        if not parts:
            # Edge case: empty file — upload a single empty part
            resp = client.upload_part(
                Bucket=bucket, Key=storage_key,
                UploadId=upload_id, PartNumber=1, Body=b"",
            )
            parts.append({"PartNumber": 1, "ETag": resp["ETag"]})

        client.complete_multipart_upload(
            Bucket=bucket,
            Key=storage_key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
    except Exception:
        client.abort_multipart_upload(Bucket=bucket, Key=storage_key, UploadId=upload_id)
        raise

    logger.info("Uploaded %s to %s (multipart fileobj, %d part(s))", storage_key, bucket, len(parts))


def download_dump(storage_key: str, local_path: str) -> None:
    """Download a dump from object storage to a local path (used in workers)."""
    import os
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
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
