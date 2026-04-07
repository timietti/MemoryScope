// frontend/src/pages/Submit.tsx
import { useState, useRef, useCallback, useEffect } from 'react'
import { useNavigate, useBlocker } from 'react-router-dom'
import { useSubmitCase } from '../hooks/useCaseWebSocket'

const PLUGIN_DOMAINS = [
  { id: 'process_analysis', label: 'Process Analysis', desc: 'pslist, pstree, cmdline, dlllist' },
  { id: 'code_injection',   label: 'Code Injection',   desc: 'malfind, vadinfo — RWX memory detection' },
  { id: 'network',          label: 'Network',           desc: 'netstat, netscan — connections & sockets' },
  { id: 'persistence',      label: 'Persistence',       desc: 'registry Run keys, services, bash history' },
  { id: 'rootkits',         label: 'Rootkits',          desc: 'modules, ssdt, lsmod — kernel artefacts' },
  { id: 'credentials',      label: 'Credentials',       desc: 'hashdump, lsadump — password hashes' },
  { id: 'filesystem',       label: 'Filesystem',        desc: 'filescan, dumpfiles — cached file objects' },
  { id: 'memory_strings',   label: 'Memory Strings',    desc: 'strings — embedded IOCs in process memory' },
]

export default function Submit() {
  const navigate = useNavigate()
  const { mutateAsync: submit } = useSubmitCase()

  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [priority, setPriority] = useState(2)
  const [osHint, setOsHint] = useState('')
  const [symbolFile, setSymbolFile] = useState<File | null>(null)
  const symbolFileRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const uploadProgressRef = useRef(0)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)
  const abortRef = useRef<AbortController | null>(null)

  // Warn before navigating away only while still uploading (not after 100%)
  const blocker = useBlocker(isSubmitting && uploadProgress < 100)

  // Warn on browser close/refresh only while still uploading (not after 100%)
  useEffect(() => {
    if (!isSubmitting || uploadProgress >= 100) return
    const handler = (e: BeforeUnloadEvent) => { e.preventDefault() }
    window.addEventListener('beforeunload', handler)
    return () => window.removeEventListener('beforeunload', handler)
  }, [isSubmitting, uploadProgress])

  // Cancel upload if component unmounts (e.g. blocker was bypassed)
  useEffect(() => {
    return () => { abortRef.current?.abort() }
  }, [])

  const handleFile = (f: File) => {
    setFile(f)
    if (!name) setName(f.name.replace(/\.(raw|mem|dmp|vmem|lime|zip)$/i, ''))
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) handleFile(f)
  }, [])

  const handleSubmit = async () => {
    if (!file || !name.trim()) return
    setIsSubmitting(true)
    setError(null)
    setUploadProgress(0)
    uploadProgressRef.current = 0

    const controller = new AbortController()
    abortRef.current = controller

    const fd = new FormData()
    fd.append('dump_file', file)
    fd.append('name', name.trim())
    fd.append('description', description)
    fd.append('priority', String(priority))
    if (osHint) fd.append('os_hint', osHint)
    if (symbolFile) fd.append('symbols_file', symbolFile)

    try {
      const case_ = await submit({
        formData: fd,
        onProgress: (v) => { setUploadProgress(v); uploadProgressRef.current = v },
        signal: controller.signal,
      })
      navigate(`/cases/${case_.id}`)
    } catch (err: any) {
      if (controller.signal.aborted) return   // user cancelled — component may be unmounting
      // Duplicate file — redirect to the existing case
      if (err?.response?.status === 409) {
        const detail = err.response.data?.detail
        const caseId = detail?.existing_case_id
        if (caseId) { navigate(`/cases/${caseId}`); return }
      }
      // If upload reached 100% AND there is no HTTP response (axios timed out
      // waiting for the server), the file was fully transferred and the case was
      // likely created. Navigate away rather than showing a spurious error.
      // If there IS a response, it's a real server error — fall through and show it.
      if (uploadProgressRef.current === 100 && !err?.response) {
        navigate('/cases')
        return
      }
      const detail = err?.response?.data?.detail
      setError(typeof detail === 'string' ? detail : (detail?.message ?? 'Upload failed. Please try again.'))
      setIsSubmitting(false)
    } finally {
      abortRef.current = null
    }
  }

  const inputStyle = {
    width: '100%',
    background: 'var(--surface2)',
    border: '1px solid var(--border2)',
    color: 'var(--text-bright)',
    fontFamily: 'var(--font-ui)',
    fontSize: 13,
    padding: '10px 14px',
    borderRadius: 5,
    outline: 'none',
  }

  const labelStyle = {
    fontFamily: 'var(--font-mono)',
    fontSize: 10,
    color: 'var(--text-dim)',
    letterSpacing: '0.12em',
    textTransform: 'uppercase' as const,
    display: 'block',
    marginBottom: 7,
  }

  return (
    <div style={{ padding: '32px 40px', maxWidth: 760 }}>
      <div style={{ marginBottom: 32 }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)', letterSpacing: '0.15em', marginBottom: 6 }}>NEW CASE</div>
        <h1 style={{ fontFamily: 'var(--font-cond)', fontSize: 28, fontWeight: 600, color: 'var(--text-bright)' }}>Submit Memory Dump</h1>
        <p style={{ color: 'var(--text-dim)', marginTop: 6, fontSize: 13 }}>Upload a raw memory dump for automated Volatility3 analysis and AI threat assessment.</p>
      </div>

      {/* Drop zone */}
      <div
        onClick={() => fileRef.current?.click()}
        onDragOver={e => { e.preventDefault(); setIsDragging(true) }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        style={{
          border: `2px dashed ${isDragging ? 'var(--accent)' : file ? 'var(--green)' : 'var(--border2)'}`,
          borderRadius: 8,
          padding: '36px 24px',
          textAlign: 'center',
          cursor: 'pointer',
          background: isDragging ? 'rgba(0,200,255,0.04)' : file ? 'rgba(46,232,138,0.04)' : 'var(--surface)',
          transition: 'all 0.15s ease',
          marginBottom: 28,
        }}
      >
        <input ref={fileRef} type="file" accept=".raw,.mem,.dmp,.vmem,.lime,.bin,.zip" style={{ display: 'none' }}
          onChange={e => e.target.files?.[0] && handleFile(e.target.files[0])} />
        {file ? (
          <>
            <div style={{ fontSize: 28, marginBottom: 8 }}>✓</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--green)' }}>{file.name}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>
              {(file.size / 1e9).toFixed(2)} GB · Click to change
            </div>
          </>
        ) : (
          <>
            <div style={{ fontSize: 32, marginBottom: 8, color: 'var(--text-dim)' }}>⬆</div>
            <div style={{ fontFamily: 'var(--font-cond)', fontSize: 15, color: 'var(--text)', marginBottom: 4 }}>Drop memory dump here or click to browse</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>.raw .mem .dmp .vmem .lime or .zip archive · Max 64 GB</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', marginTop: 4, opacity: 0.7 }}>ZIP may contain VMEM + VMSS/VMSN companion pair</div>
          </>
        )}
      </div>

      {/* Form fields */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <div style={{ gridColumn: '1 / -1' }}>
          <label style={labelStyle}>Case Name *</label>
          <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. ACME-Workstation-2024-01-15" style={inputStyle} />
        </div>
        <div>
          <label style={labelStyle}>Priority</label>
          <select value={priority} onChange={e => setPriority(+e.target.value)} style={inputStyle}>
            <option value={1}>1 — Low</option>
            <option value={2}>2 — Medium</option>
            <option value={3}>3 — High</option>
            <option value={4}>4 — Critical</option>
          </select>
        </div>
        <div>
          <label style={labelStyle}>OS Hint (optional)</label>
          <select value={osHint} onChange={e => { setOsHint(e.target.value); setSymbolFile(null) }} style={inputStyle}>
            <option value="">Auto-detect</option>
            <option value="windows">Windows</option>
            <option value="linux">Linux</option>
            <option value="macos">macOS</option>
          </select>
        </div>
        {(osHint === 'linux' || osHint === 'macos') && (
          <div style={{ gridColumn: '1 / -1' }}>
            <label style={labelStyle}>
              Symbol Table (optional)
              <span style={{ color: 'var(--text-dim)', fontWeight: 400, marginLeft: 8 }}>
                .json or .json.xz — upload a matching Volatility3 ISF if auto-build is unavailable
              </span>
            </label>
            <input
              ref={symbolFileRef}
              type="file"
              accept=".json,.xz"
              style={{ display: 'none' }}
              onChange={e => setSymbolFile(e.target.files?.[0] ?? null)}
            />
            <div
              onClick={() => symbolFileRef.current?.click()}
              style={{
                ...inputStyle,
                cursor: 'pointer',
                color: symbolFile ? 'var(--green)' : 'var(--text-dim)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <span>{symbolFile ? symbolFile.name : 'Click to select symbol table file…'}</span>
              {symbolFile && (
                <span
                  onClick={e => { e.stopPropagation(); setSymbolFile(null); if (symbolFileRef.current) symbolFileRef.current.value = '' }}
                  style={{ color: 'var(--text-dim)', fontSize: 12, cursor: 'pointer' }}
                >✕ Remove</span>
              )}
            </div>
          </div>
        )}
        <div style={{ gridColumn: '1 / -1' }}>
          <label style={labelStyle}>Description</label>
          <textarea value={description} onChange={e => setDescription(e.target.value)} rows={3}
            placeholder="Context about this system, suspected incident, collection method..."
            style={{ ...inputStyle, resize: 'vertical', lineHeight: 1.7 }} />
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{ background: 'rgba(255,61,87,0.08)', border: '1px solid rgba(255,61,87,0.3)', borderRadius: 5, padding: '12px 16px', marginBottom: 16, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--red)' }}>
          {error}
        </div>
      )}

      {/* Upload progress */}
      {isSubmitting && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)' }}>
              {uploadProgress < 100 ? 'Uploading...' : 'Queuing analysis...'}
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>{uploadProgress}%</span>
          </div>
          <div style={{ height: 3, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${uploadProgress}%`, background: 'var(--accent)', transition: 'width 0.2s ease' }} />
          </div>
        </div>
      )}

      {/* Submit */}
      <div style={{ display: 'flex', gap: 12 }}>
        <button
          onClick={handleSubmit}
          disabled={!file || !name.trim() || isSubmitting}
          style={{
            background: !file || !name.trim() || isSubmitting ? 'var(--border2)' : 'var(--accent)',
            color: !file || !name.trim() || isSubmitting ? 'var(--text-dim)' : 'var(--bg)',
            border: 'none',
            fontFamily: 'var(--font-cond)',
            fontSize: 14,
            fontWeight: 600,
            letterSpacing: '0.08em',
            padding: '12px 28px',
            borderRadius: 5,
            cursor: !file || !name.trim() || isSubmitting ? 'not-allowed' : 'pointer',
            textTransform: 'uppercase',
          }}
        >
          {isSubmitting ? 'Submitting...' : 'Submit for Analysis'}
        </button>
        <button
          onClick={() => navigate('/cases')}
          disabled={isSubmitting}
          style={{ background: 'none', border: '1px solid var(--border2)', color: 'var(--text-dim)', fontFamily: 'var(--font-cond)', fontSize: 13, padding: '12px 20px', borderRadius: 5, cursor: 'pointer', textTransform: 'uppercase', letterSpacing: '0.06em' }}
        >
          Cancel
        </button>
      </div>

      {/* Navigation blocker dialog */}
      {blocker.state === 'blocked' && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
        }}>
          <div style={{
            background: 'var(--surface2)', border: '1px solid var(--border2)',
            borderRadius: 8, padding: '28px 32px', maxWidth: 420, width: '90%',
          }}>
            <div style={{ fontFamily: 'var(--font-cond)', fontSize: 16, fontWeight: 600, color: 'var(--text-bright)', marginBottom: 10 }}>
              Cancel upload?
            </div>
            <div style={{ fontFamily: 'var(--font-ui)', fontSize: 13, color: 'var(--text-dim)', marginBottom: 24, lineHeight: 1.6 }}>
              The upload is {uploadProgress}% complete. Leaving now will cancel the transfer and no case will be created.
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button
                onClick={() => { abortRef.current?.abort(); blocker.proceed() }}
                style={{ background: 'var(--red)', color: '#fff', border: 'none', fontFamily: 'var(--font-cond)', fontSize: 13, fontWeight: 600, padding: '10px 20px', borderRadius: 5, cursor: 'pointer', textTransform: 'uppercase', letterSpacing: '0.06em' }}
              >
                Cancel upload
              </button>
              <button
                onClick={() => blocker.reset()}
                style={{ background: 'none', border: '1px solid var(--border2)', color: 'var(--text-dim)', fontFamily: 'var(--font-cond)', fontSize: 13, padding: '10px 20px', borderRadius: 5, cursor: 'pointer', textTransform: 'uppercase', letterSpacing: '0.06em' }}
              >
                Keep uploading
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
