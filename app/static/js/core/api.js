let errorListener = () => {};
export const onApiError = (listener) => {
  errorListener = listener;
};
async function request(path, body, signal) {
  try {
    const response = await fetch(`/api/${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      signal,
      ...(body === undefined
        ? {}
        : {
            headers: { 'Content-Type': 'application/json', 'X-Lab-Request': '1' },
            body: JSON.stringify(body),
          }),
    });
    let data;
    try {
      data = await response.json();
    } catch {
      return {
        ok: false,
        status: response.status,
        error: { code: 'bad_response', message: 'Invalid JSON', retryable: true },
      };
    }
    if (!response.ok) {
      const result = {
        ok: false,
        status: response.status,
        error: data?.error ?? { code: 'bad_response', message: String(response.status) },
      };
      errorListener(result);
      return result;
    }
    return { ok: true, data };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      error: {
        code: e.name === 'AbortError' ? 'aborted' : 'network_error',
        message: 'Connection interrupted',
        retryable: true,
      },
    };
  }
}
function checked(result, valid) {
  if (result.ok && !valid(result.data))
    return {
      ok: false,
      status: 200,
      error: { code: 'bad_response', message: 'Invalid response shape', retryable: true },
    };
  return result;
}
const snapshot = (result) =>
  checked(
    result,
    (data) =>
      data &&
      typeof data.scan_id === 'string' &&
      typeof data.server_instance_id === 'string' &&
      typeof data.state === 'string' &&
      data.tools &&
      typeof data.tools === 'object' &&
      !Array.isArray(data.tools),
  );
export const api = {
  reportPDF: async (id) => {
    try {
      const response = await fetch(`/api/scans/${encodeURIComponent(id)}/report.pdf`, {
        credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      });
      if (!response.ok) {
        const data = await response.json();
        const result = { ok: false, status: response.status, error: data.error ?? {
          code: 'export_failed', message: 'PDF export failed.', retryable: true,
        } };
        errorListener(result);
        return result;
      }
      if (!response.headers.get('Content-Type')?.startsWith('application/pdf'))
        throw Error('Invalid PDF response');
      const blob = await response.blob();
      const disposition = response.headers.get('Content-Disposition') ?? '';
      const match = disposition.match(/^attachment; filename="(penchecker-[0-9a-f-]{36}-r[1-9][0-9]*\.pdf)"$/);
      const filename = match?.[1]?.startsWith(`penchecker-${id}-r`)
        ? match[1] : `penchecker-${id}.pdf`;
      return { ok: true, blob, filename };
    } catch {
      return { ok: false, status: 0, error: { code: 'export_failed',
        message: 'Could not download PDF. Please try again.', retryable: true } };
    }
  },
  capabilities: async () => {
    const result = checked(
      await request('capabilities'),
      (data) =>
        data &&
        typeof data.server_instance_id === 'string' &&
        data.target &&
        typeof data.target.target_id === 'string' &&
        Array.isArray(data.tools) &&
        Array.isArray(data.providers),
    );
    if (result.ok) {
      // Discard accidental secret values before any consumer sees capabilities.
      result.data.settings = Array.isArray(result.data.settings)
        ? result.data.settings.map((row) =>
            row.secret || row.kind === 'secret_state'
              ? { ...row, value: null, display_value: null }
              : row,
          )
        : undefined;
    }
    return result;
  },
  recent: async (offset = 0) =>
    checked(await request(`scans?offset=${offset}&limit=10`),
      (data) => data && Array.isArray(data.scans)),
  providers: async () => checked(await request('settings/providers'),
    (data) => data && Array.isArray(data.providers)),
  deleteProvider: async (id) => request(`settings/providers/${encodeURIComponent(id)}/delete`, {}),
  saveProvider: async (id, body) => request(id ? `settings/providers/${encodeURIComponent(id)}` : 'settings/providers', body),
  aiSettings: async () => request('settings/ai'),
  saveAISettings: async (body) => request('settings/ai', body),
  scan: async (id) => snapshot(await request(`scans/${encodeURIComponent(id)}`)),
  cves: async (id) => snapshot(await request(`scans/${encodeURIComponent(id)}/cves`, {})),
  start: async (body) => snapshot(await request('scans', body)),
  cancel: async (id) =>
    snapshot(await request(`scans/${encodeURIComponent(id)}/cancel`, {})),
  retry: async (id, provider_id) =>
    snapshot(await request(`scans/${encodeURIComponent(id)}/analysis`, { provider_id })),
  output: async (id, tool, stream, offset, signal) =>
    checked(
      await request(
        `scans/${encodeURIComponent(id)}/tools/${encodeURIComponent(tool)}/output?${new URLSearchParams({ stream, offset, limit: 16384 })}`,
        undefined,
        signal,
      ),
      (data) =>
        data &&
        typeof data.text === 'string' &&
        Number.isInteger(data.next_offset) &&
        data.next_offset >= 0 &&
        typeof data.has_more === 'boolean',
    ),
};
