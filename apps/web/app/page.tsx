import ScanList from "@/components/scan/ScanList";

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Scans</h1>
          <p className="mt-1 text-sm text-zinc-500">
            Security regression runs against the built-in ShopHelper demo bot.
          </p>
        </div>
      </div>
      <ScanList />
    </div>
  );
}
