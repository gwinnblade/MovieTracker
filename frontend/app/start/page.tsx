"use client";
import Link from "next/link";
import { useAuth } from "@/components/Auth";
export default function Start() {
  const { user } = useAuth();
  return (
    <div className="empty-state panel">
      <h1>Твои истории ждут</h1>
      <Link
        className="button"
        href={user ? "/profile" : "/login?next=/profile"}
      >
        Начать учёт
      </Link>
    </div>
  );
}
