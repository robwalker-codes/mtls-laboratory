// Keep the live record visible without moving the reader away from the teaching panel.
// The TLS engine and all experiment state remain in the .NET backend.
export function revealRecord(id) {
    const row = document.getElementById(id);
    const viewport = row?.closest('.record-scroll');
    if (!row || !viewport) return;
    const bounds = row.getBoundingClientRect();
    const frame = viewport.getBoundingClientRect();
    if (bounds.top < frame.top || bounds.bottom > frame.bottom) {
        viewport.scrollTop += bounds.top - frame.top - 16;
    }
}
