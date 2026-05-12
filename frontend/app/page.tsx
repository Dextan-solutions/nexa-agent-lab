export default function HomePage() {
  return (
    <main className="mx-auto flex min-h-screen max-w-[1000px] flex-col justify-center px-6 py-12">
      <div className="rounded-2xl border bg-card p-8 shadow-sm">
        <div className="text-sm font-medium text-muted-foreground">NexaBank</div>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight">Digital banking portal</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Account overview, transactions, loan applications, KYC verification, and support.
        </p>
        <div className="mt-6 flex gap-3">
          <a
            className="inline-flex h-10 items-center justify-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground hover:opacity-90"
            href="/dashboard"
          >
            Open dashboard
          </a>
          <a
            className="inline-flex h-10 items-center justify-center rounded-md border px-4 text-sm font-medium hover:bg-accent"
            href="/support"
          >
            Contact support
          </a>
        </div>
      </div>
    </main>
  );
}

