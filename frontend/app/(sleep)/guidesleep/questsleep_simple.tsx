// import React, { useMemo, useState } from "react";
// import { Alert, Text, TouchableOpacity, View } from "react-native";

// // สมมติว่านี่คือข้อมูลเควสที่ดึงมาจาก Database ของน้อง
// const initialQuests = [
//   { id: 1, text: "Take a warm bath before bed", score: 20 },
//   { id: 2, text: "Sleep 7-9 hours", score: 20 },
// ];

// export default function QuestSleepScreen() {
//   // 1. สร้าง State เก็บสถานะของแต่ละเควส
//   // รูปแบบ: { 1: 'completed', 2: 'in_progress' }
//   const [questStatuses, setQuestStatuses] = useState({});

//   // 2. ฟังก์ชันคำนวณคะแนนรวม (จะคำนวณใหม่ทุกครั้งที่ questStatuses เปลี่ยน)
//   // นี่คือหัวใจสำคัญ! มันจะนับคะแนนเฉพาะอันที่เป็น 'completed' เท่านั้น
//   const totalScore = useMemo(() => {
//     let score = 0;
//     initialQuests.forEach((quest) => {
//       if (questStatuses[quest.id] === "completed") {
//         score += quest.score;
//       }
//     });
//     return score;
//   }, [questStatuses]);

//   // 3. ฟังก์ชันเวลากดปุ่มต่างๆ
//   const handleMarkComplete = (questId) => {
//     setQuestStatuses((prev) => ({ ...prev, [questId]: "completed" }));
//   };

//   const handleMarkIncomplete = (questId) => {
//     // เปลี่ยนสถานะเป็นอย่างอื่น (คะแนนที่เคยได้จะหายไปทันที เพราะหลุดเงื่อนไข completed)
//     setQuestStatuses((prev) => ({ ...prev, [questId]: "failed" }));
//   };

//   const handleResetAll = () => {
//     Alert.alert("ยืนยัน", "ต้องการล้างสถานะทั้งหมดใช่หรือไม่?", [
//       { text: "ยกเลิก", style: "cancel" },
//       {
//         text: "ล้างสถานะ",
//         style: "destructive",
//         onPress: () => {
//           // เคลียร์ State ทั้งหมด คะแนนรวมจะกลับเป็น 0 ทันที
//           setQuestStatuses({});
//         },
//       },
//     ]);
//   };

//   return (
//     <View style={{ flex: 1, padding: 20 }}>
//       {/* ส่วนแสดงเควส */}
//       {initialQuests.map((quest) => (
//         <View
//           key={quest.id}
//           style={{ marginBottom: 20, borderWidth: 1, padding: 10 }}
//         >
//           <Text>
//             {quest.text} (คะแนน: {quest.score})
//           </Text>
//           <Text>
//             สถานะปัจจุบัน: {questStatuses[quest.id] || "ยังไม่ได้เริ่ม"}
//           </Text>

//           <View style={{ flexDirection: "row", marginTop: 10, gap: 10 }}>
//             <TouchableOpacity
//               onPress={() => handleMarkComplete(quest.id)}
//               style={{ backgroundColor: "green", padding: 5 }}
//             >
//               <Text style={{ color: "white" }}>ทำเสร็จ</Text>
//             </TouchableOpacity>

//             <TouchableOpacity
//               onPress={() => handleMarkIncomplete(quest.id)}
//               style={{ backgroundColor: "orange", padding: 5 }}
//             >
//               <Text style={{ color: "white" }}>ทำไม่เสร็จ</Text>
//             </TouchableOpacity>
//           </View>
//         </View>
//       ))}

//       {/* ส่วนสรุปคะแนน */}
//       <View style={{ marginTop: 30, padding: 10, backgroundColor: "#eee" }}>
//         <Text style={{ fontSize: 18, fontWeight: "bold" }}>
//           คะแนนรวม: {totalScore}
//         </Text>
//       </View>

//       {/* ปุ่มรีเซ็ต */}
//       <TouchableOpacity
//         onPress={handleResetAll}
//         style={{
//           backgroundColor: "red",
//           padding: 15,
//           marginTop: 20,
//           alignItems: "center",
//         }}
//       >
//         <Text style={{ color: "white", fontWeight: "bold" }}>
//           รีเซ็ตสถานะยืนยัน (ล้าง)
//         </Text>
//       </TouchableOpacity>
//     </View>
//   );
// }
