// app/(sleep)/guidesleep/services/api.ts
import axios from "axios";
import axiosInstance from "../../../../src/config/axiosInstance";

const BACKEND = axiosInstance.defaults.baseURL || "http://192.168.1.2:8000";

type GuidePost = any;

/**
 * getGuideSleepPosts
 * - พยายามเรียกผ่าน axiosInstance (แนบ token อัตโนมัติถ้ามี)
 * - ถ้าได้รับ 401 จะพยายาม fallback ไปยัง endpoint สาธารณะ (/guidesleep/public)
 * - ถ้า fallback ไม่สำเร็จ จะคืน array ว่างให้ caller แสดง placeholder แทน (ไม่โยน error ขึ้น console)
 */
export async function getGuideSleepPosts(): Promise<GuidePost[]> {
  try {
    const res = await axiosInstance.get("/guidesleep");
    return Array.isArray(res.data) ? res.data : [];
  } catch (err: any) {
    const status = err?.response?.status;
    if (status === 401) {
      // พยายามเรียก public endpoint โดยไม่แนบ Authorization
      try {
        const fallback = await axios.get(`${BACKEND}/guidesleep/public`, {
          headers: { Accept: "application/json" },
        });
        return Array.isArray(fallback.data) ? fallback.data : [];
      } catch {
        // fallback ล้มเหลว ให้คืน array ว่าง (caller จะแสดง placeholder) — ไม่โยน error 401 ขึ้น console
        return [];
      }
    }
    // ข้อผิดพลาดอื่น ๆ: พยายาม fallback public ก่อน แล้วคืน array ว่าง
    try {
      const fallback = await axios.get(`${BACKEND}/guidesleep/public`, {
        headers: { Accept: "application/json" },
      });
      return Array.isArray(fallback.data) ? fallback.data : [];
    } catch {
      return [];
    }
  }
}

/**
 * createReport
 * - แนบ token ผ่าน axiosInstance (ถ้ามี)
 */
export async function createReport(payload: {
  target_type: string;
  target_id: number;
  reason: string;
}) {
  const res = await axiosInstance.post("/reports", payload);
  return res.data;
}

/**
 * fetchPublicGuides (explicit)
 * - เรียก public endpoint โดยตรง (ใช้เมื่อ caller ต้องการบังคับ public)
 */
export async function fetchPublicGuides(): Promise<GuidePost[]> {
  try {
    const res = await axios.get(`${BACKEND}/guidesleep/public`, {
      headers: { Accept: "application/json" },
    });
    return Array.isArray(res.data) ? res.data : [];
  } catch {
    return [];
  }
}
