import React from "react";
import { View, Text } from "react-native";

export default function StatCard({ title, value }: { title: string; value: string }) {
  return (
    <View style={{ flex:1, backgroundColor:"#fff", padding:12, borderRadius:8, marginRight:8 }}>
      <Text style={{ fontSize:14, color:"#666" }}>{title}</Text>
      <Text style={{ fontSize:20, fontWeight:"800", marginTop:6 }}>{value}</Text>
    </View>
  );
}
