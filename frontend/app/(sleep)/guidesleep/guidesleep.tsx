// app/(sleep)/guidesleep/guidesleep.tsx
import React, { Suspense, lazy } from 'react';
import { ActivityIndicator, View, Text, StyleSheet } from 'react-native';
import { createMaterialTopTabNavigator } from '@react-navigation/material-top-tabs';
import MaterialCommunityIcons from 'react-native-vector-icons/MaterialCommunityIcons';

const Tab = createMaterialTopTabNavigator();

// Lazy load each screen — each screen should manage its own scrolling (FlatList/ScrollView) to avoid nested VirtualizedLists
const QuickScreen = lazy(() => import('./quick'));
const FreshScreen = lazy(() => import('./fresh'));
const PostureScreen = lazy(() => import('./posture'));
const HelperScreen = lazy(() => import('./helper'));

const categories = [
  {
    key: 'quick',
    title: 'แนะนำหลับเร็ว',
    icon: 'weather-night',
    component: QuickScreen,
  },
  {
    key: 'fresh',
    title: 'ตื่นนอนให้สดชื่น',
    icon: 'white-balance-sunny',
    component: FreshScreen,
  },
  {
    key: 'posture',
    title: 'ท่านอนที่เหมาะสม',
    icon: 'bed',
    component: PostureScreen,
  },
  {
    key: 'helper',
    title: 'ตัวช่วยนอนหลับ',
    icon: 'meditation',
    component: HelperScreen,
  },
];

function TabFallback() {
  return (
    <View style={styles.fallback}>
      <ActivityIndicator size="large" color="#007AFF" />
    </View>
  );
}

/**
 * GuidesleepTabs
 *
 * Notes:
 * - Each tab's component is wrapped in Suspense and a full-height container so the child can own scrolling.
 * - Avoid wrapping these screens in a parent ScrollView; if you previously had a ScrollView in a parent,
 *   remove it or ensure it does not contain a VirtualizedList (FlatList/SectionList) with the same orientation.
 * - Use `sceneContainerStyle` so each tab scene has a consistent background.
 */
export default function GuidesleepTabs() {
  return (
    <Tab.Navigator
      initialRouteName="quick"
      screenOptions={{
        tabBarIndicatorStyle: { backgroundColor: '#007AFF' },
        tabBarLabelStyle: { fontSize: 10, fontWeight: '600' },
        tabBarStyle: { backgroundColor: '#fff' },
        swipeEnabled: true,
        lazy: true,
        sceneContainerStyle: { backgroundColor: '#fff' },
      }}
    >
      {categories.map(({ key, title, icon, component: Component }) => (
        <Tab.Screen
          key={key}
          name={key}
          options={{
            tabBarLabel: ({ focused, color }) => (
              <View style={styles.tabLabel}>
                <MaterialCommunityIcons
                  name={icon}
                  size={14}
                  color={focused ? '#007AFF' : '#999'}
                  style={styles.tabIcon}
                />
                <Text style={[styles.tabText, { color }]} numberOfLines={1}>
                  {title}
                </Text>
              </View>
            ),
          }}
        >
          {() => (
            <Suspense fallback={<TabFallback />}>
              {/* wrapper ensures the child fills available space and can manage its own scroll */}
              <View style={styles.screenWrapper}>
                <Component />
              </View>
            </Suspense>
          )}
        </Tab.Screen>
      ))}
    </Tab.Navigator>
  );
}

const styles = StyleSheet.create({
  fallback: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  screenWrapper: {
    flex: 1,
    backgroundColor: '#fff',
  },
  tabLabel: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  tabIcon: {
    marginRight: 6,
  },
  tabText: {
    fontSize: 10,
    fontWeight: '600',
  },
});
