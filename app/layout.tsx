import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "CodeVibes Thin UI",
  description: "Analyze local repos and GitHub URLs with CodeVibes.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

