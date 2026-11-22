import './globals.css'
import type { Metadata } from 'next'
import { Inter } from 'next/font/google'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'AI Password Auditor - Security Intelligence Lab',
  description: 'Intelligent password strength assessment and machine learning security risk prediction system.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body class={`${inter.className} cyber-grid`}>{children}</body>
    </html>
  )
}
