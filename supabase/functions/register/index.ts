// TAJ STORE — registration with phone number + password.
// Creates a confirmed auth user (login e-mail is derived from the phone) and its profile.
// The very first account becomes Admin.
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const out = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

export const phoneDigits = (p: string) => {
  let d = String(p || "").replace(/\D/g, "");
  if (d.length === 9) d = "992" + d;
  return d;
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return out(405, { error: "method" });
  let b: { name?: string; phone?: string; password?: string };
  try { b = await req.json(); } catch { return out(400, { error: "json" }); }
  const name = String(b.name || "").trim().slice(0, 60);
  const ph = phoneDigits(b.phone || "");
  const pw = String(b.password || "");
  if (name.length < 2) return out(400, { error: "name" });
  if (ph.length < 9 || ph.length > 13) return out(400, { error: "phone" });
  if (pw.length < 6 || pw.length > 72) return out(400, { error: "password" });

  const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const email = `t${ph}@tajstore.app`;
  const { data, error } = await sb.auth.admin.createUser({
    email, password: pw, email_confirm: true, user_metadata: { name, phone: "+" + ph },
  });
  if (error || !data?.user) {
    const dup = /already|exists|registered/i.test(error?.message || "");
    return out(dup ? 409 : 400, { error: dup ? "dup" : "auth", detail: error?.message || "" });
  }
  const r = await sb.rpc("register_profile", { p_id: data.user.id, p_name: name, p_phone: "+" + ph });
  if (r.error) {
    await sb.auth.admin.deleteUser(data.user.id);
    return out(500, { error: "profile", detail: r.error.message });
  }
  return out(200, { ok: true, email, ...(r.data as Record<string, unknown>) });
});
