import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Penetration Testing Playbook",
  description: "Comprehensive Activity 4 & 5 pentesting presentation"
};

export default function RootLayout({
  children
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <head />
      <body>{children}</body>
    </html>
  );
}
