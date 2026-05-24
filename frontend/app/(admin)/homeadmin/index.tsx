// app/(admin)/homeadmin/index.tsx
import React, { Suspense, lazy } from "react";
import { ActivityIndicator, SafeAreaView, View, Text, StyleSheet } from "react-native";
import { createMaterialTopTabNavigator } from "@react-navigation/material-top-tabs";

const Tab = createMaterialTopTabNavigator();

// Lazy load each screen (paths should match your project structure)
const DashboardScreen = lazy(() => import("./dashboard"));
const ReportScreen = lazy(() => import("./report"));
const AddQuestScreen = lazy(() => import("./addquest"));

const tabs = [
  { key: "dashboard", title: "Dashboard", component: DashboardScreen },
  { key: "report", title: "Report", component: ReportScreen },
  { key: "addquest", title: "Addquest", component: AddQuestScreen },
];

export default function AdminHomeTabs() {
  return (
    <SafeAreaView style={styles.safe}>
      <View style={styles.header}>
        <Text style={styles.logo}>Homeadmin</Text>
      </View>

      <Tab.Navigator
        initialRouteName="Dashboard"
        screenOptions={{
          tabBarIndicatorStyle: { backgroundColor: "#007AFF", height: 3 },
          tabBarLabelStyle: { fontSize: 14, fontWeight: "700" },
          tabBarStyle: { backgroundColor: "#fff" },
          swipeEnabled: true,
          // ให้แต่ละ scene มี container ของตัวเอง (ช่วยให้ child ควบคุมการเลื่อนได้)
          sceneContainerStyle: { flex: 1, backgroundColor: "#fff" },
        }}
      >
        {tabs.map(({ key, title, component: Component }) => (
          <Tab.Screen
            key={key}
            name={title}
            options={{ title }}
          >
            {() => (
              <Suspense
                fallback={
                  <View style={styles.loading}>
                    <ActivityIndicator size="large" />
                  </View>
                }
              >
                {/* ห่อด้วย View ที่มี flex:1 เพื่อให้ child เป็นเจ้าของการเลื่อน */}
                <View style={styles.screenWrapper}>
                  <Component />
                </View>
              </Suspense>
            )}
          </Tab.Screen>
        ))}
      </Tab.Navigator>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: "#f7f7f7" },
  header: {
    height: 64,
    backgroundColor: "#fff",
    borderBottomWidth: 1,
    borderBottomColor: "#eee",
    justifyContent: "center",
    alignItems: "center",
  },
  logo: { fontSize: 20, fontWeight: "800", color: "#222" },
  loading: { flex: 1, justifyContent: "center", alignItems: "center" },
  screenWrapper: { flex: 1, backgroundColor: "#fff" },
});
