export default function ReportsPage() {
  return (
    <main className="page-shell min-h-screen bg-[#0d0202] text-white pt-24">
      <div className="page-container">
        <h1 className="text-2xl font-semibold text-white/80 mb-2">Reports</h1>
        <p className="text-sm text-white/30" style={{ fontFamily: "var(--font-space-mono)" }}>
          No reports yet. Complete a scan to generate an illuminated report.
        </p>
      </div>
    </main>
  );
}
