import NewScanForm from "@/components/scan/NewScanForm";

export default function NewScanPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">New scan</h1>
        <p className="mt-1 text-sm text-zinc-500">
          Configure a bounded security regression run. Attack count, retries,
          timeouts, and model-call budgets are enforced.
        </p>
      </div>
      <NewScanForm />
    </div>
  );
}
