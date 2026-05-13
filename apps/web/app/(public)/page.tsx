import {
  ApiPreview,
  FeatureGrid,
  Hero,
  HowItWorks,
  SecuritySection,
} from "@/components/marketing/sections";
import { PageShell } from "@/components/layout/site-shell";

export default function AtHomePage() {
  return (
    <PageShell>
      <main>
        <Hero />
        <FeatureGrid />
        <HowItWorks />
        <ApiPreview />
        <SecuritySection />
      </main>
    </PageShell>
  );
}
