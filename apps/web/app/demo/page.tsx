import Demo from "@/components/ui/demo";
import TopBar from "@/components/ui/TopBar";

export default function DemoPage() {
  return (
    <div className="flex flex-col min-h-full">
      <TopBar breadcrumbs={[{ label: "Mission Control", href: "/" }, { label: "Interactive Attack Showcase" }]} />
      <main className="flex-1 p-6">
        <Demo />
      </main>
    </div>
  );
}
