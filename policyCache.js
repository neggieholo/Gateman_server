import pool from "./db.js";

let systemPolicyCache = null;
let cacheLoadedAt = 0;
const CACHE_TTL_MS = 30 * 1000; // 30 seconds

export const loadPoliciesIntoMemory = async (db = pool) => {
  const result = await db.query("SELECT * FROM system_policies WHERE id = 1");
  systemPolicyCache = result.rows[0] || null;
  cacheLoadedAt = Date.now();
  return systemPolicyCache;
};

export const getCachedPolicies = async (db = pool) => {
  const isExpired = !systemPolicyCache || Date.now() - cacheLoadedAt > CACHE_TTL_MS;
  if (isExpired) {
    return await loadPoliciesIntoMemory(db);
  }
  return systemPolicyCache;
};