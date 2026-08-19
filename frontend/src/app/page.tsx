import { redirect } from "next/navigation";

/**
 * Root page — redirects to the default locale.
 * All content lives under /[locale]/page.tsx.
 */
export default function RootPage() {
  redirect("/en");
}
