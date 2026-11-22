import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-partner-session",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { ...cors, "Content-Type": "application/json" },
});

const url = Deno.env.get("SUPABASE_URL")!;
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const pepper = Deno.env.get("CODE_PEPPER");
const db = createClient(url, serviceKey, { auth: { persistSession: false } });

function bytesToHex(bytes: Uint8Array) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256(value: string) {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}
async function codeHash(code: string) {
  if (!pepper) throw new Error("CODE_PEPPER não configurado no servidor");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(code));
  return bytesToHex(new Uint8Array(sig));
}
function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToHex(bytes);
}
function randomPartnerCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return [...bytes].map((b) => alphabet[b % alphabet.length]).join("");
}
async function requireAdmin(req: Request) {
  const auth = req.headers.get("authorization") || "";
  const jwt = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!jwt) return null;
  const { data: userData, error: userError } = await db.auth.getUser(jwt);
  if (userError || !userData.user) return null;
  const { data: admin, error } = await db.from("traffic_admins").select("user_id,active").eq("user_id", userData.user.id).eq("active", true).maybeSingle();
  if (error || !admin) return null;
  return userData.user;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Método não permitido." }, 405);
  try {
    const body = await req.json();
    const action = String(body.action || "");

    if (action === "partner_login") {
      const code = String(body.code || "").trim().toUpperCase();
      if (!/^[A-Z0-9]{3,20}$/.test(code)) return json({ error: "Código inválido." }, 400);
      const forwarded = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
      const ipHash = await sha256(`${pepper}:${forwarded}`);
      const { data: allowed, error: limitError } = await db.rpc("consume_partner_login_attempt", { p_ip_hash: ipHash });
      if (limitError || allowed !== true) return json({ error: "Demasiadas tentativas. Tenta novamente dentro de 15 minutos." }, 429);

      const hash = await codeHash(code);
      const { data: access, error } = await db.from("partner_access_codes")
        .select("partner_id,partners!inner(id,display_name,active)")
        .eq("code_hash", hash).eq("active", true).maybeSingle();
      if (error || !access || !access.partners?.active) return json({ error: "Código incorrecto ou desactivado." }, 401);

      const token = randomToken();
      const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString();
      const { error: sessionError } = await db.from("partner_sessions").insert({
        partner_id: access.partner_id,
        token_hash: await sha256(token),
        expires_at: expiresAt,
      });
      if (sessionError) throw sessionError;
      return json({ token, expires_at: expiresAt, partner_id: access.partner_id, partner_name: access.partners.display_name });
    }

    if (action === "partner_session") {
      const token = req.headers.get("x-partner-session") || "";
      if (!token) return json({ error: "Sessão não encontrada." }, 401);
      const { data: session } = await db.from("partner_sessions")
        .select("partner_id,expires_at,revoked_at,partners!inner(id,display_name,active)")
        .eq("token_hash", await sha256(token)).is("revoked_at", null).gt("expires_at", new Date().toISOString()).maybeSingle();
      if (!session || !session.partners?.active) return json({ error: "Sessão expirada ou revogada." }, 401);
      return json({ valid: true, partner_id: session.partner_id, partner_name: session.partners.display_name, expires_at: session.expires_at });
    }

    if (action === "partner_logout") {
      const token = req.headers.get("x-partner-session") || "";
      if (token) await db.from("partner_sessions").update({ revoked_at: new Date().toISOString() }).eq("token_hash", await sha256(token)).is("revoked_at", null);
      return json({ ok: true });
    }

    const admin = await requireAdmin(req);
    if (!admin) return json({ error: "Acesso administrativo não autorizado." }, 403);

    if (action === "admin_list") {
      const { data, error } = await db.from("partners").select("id,display_name,active,partner_access_codes(active,created_at)").order("id");
      if (error) throw error;
      return json({ partners: data.map((p: any) => ({ id: p.id, display_name: p.display_name, active: p.active, has_active_code: (p.partner_access_codes || []).some((c: any) => c.active) })) });
    }

    if (action === "admin_bootstrap") {
      const { count, error: countError } = await db.from("partner_access_codes").select("id", { count: "exact", head: true }).eq("active", true);
      if (countError) throw countError;
      if ((count || 0) > 0) return json({ error: "Os códigos iniciais já foram configurados. Usa Gerar novo código." }, 409);
      const initial = ["001", "002", "003", "004"];
      const rows = await Promise.all(initial.map(async (code, idx) => ({ partner_id: idx + 1, code_hash: await codeHash(code), created_by: admin.id })));
      const { error } = await db.from("partner_access_codes").insert(rows);
      if (error) throw error;
      return json({ codes: initial.map((code, idx) => ({ partner_id: idx + 1, code })) });
    }

    if (action === "admin_rotate") {
      const partnerId = Number(body.partner_id);
      if (![1, 2, 3, 4].includes(partnerId)) return json({ error: "Parceiro inválido." }, 400);
      const code = randomPartnerCode();
      const now = new Date().toISOString();
      await db.from("partner_access_codes").update({ active: false, revoked_at: now }).eq("partner_id", partnerId).eq("active", true);
      await db.from("partner_sessions").update({ revoked_at: now }).eq("partner_id", partnerId).is("revoked_at", null);
      const { error } = await db.from("partner_access_codes").insert({ partner_id: partnerId, code_hash: await codeHash(code), created_by: admin.id });
      if (error) throw error;
      await db.from("partners").update({ active: true, updated_at: now }).eq("id", partnerId);
      return json({ partner_id: partnerId, code });
    }

    if (action === "admin_revoke") {
      const partnerId = Number(body.partner_id);
      if (![1, 2, 3, 4].includes(partnerId)) return json({ error: "Parceiro inválido." }, 400);
      const now = new Date().toISOString();
      await db.from("partner_access_codes").update({ active: false, revoked_at: now }).eq("partner_id", partnerId).eq("active", true);
      await db.from("partner_sessions").update({ revoked_at: now }).eq("partner_id", partnerId).is("revoked_at", null);
      await db.from("partners").update({ active: false, updated_at: now }).eq("id", partnerId);
      return json({ ok: true });
    }

    if (action === "admin_activate") {
      const partnerId = Number(body.partner_id);
      if (![1, 2, 3, 4].includes(partnerId)) return json({ error: "Parceiro inválido." }, 400);
      const { error } = await db.from("partners").update({ active: true, updated_at: new Date().toISOString() }).eq("id", partnerId);
      if (error) throw error;
      return json({ ok: true });
    }

    return json({ error: "Acção desconhecida." }, 400);
  } catch (err) {
    console.error("traffic-auth error", err);
    return json({ error: "Erro interno. Verifica a configuração do servidor." }, 500);
  }
});
