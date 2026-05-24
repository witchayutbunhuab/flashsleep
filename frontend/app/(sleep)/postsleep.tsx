import { View, Text, TouchableOpacity, FlatList, StyleSheet } from 'react-native';
import { useRouter } from 'expo-router';

// หมวดหมู่หลัก
const categories = [
  { key: 'quick', title: 'แนะนำหลับเร็ว' },
  { key: 'fresh', title: 'ตื่นนอนให้สดชื่น' },
  { key: 'posture', title: 'ท่านอนที่เหมาะสม' },
  { key: 'helper', title: 'ตัวช่วยนอนหลับ' },
];

// ตัวอย่างโพสต์ (mock)
const posts = [
  { id: '1', title: 'Snow Life', category: 'quick', duration: '7:55 ชม.' },
  { id: '2', title: 'วงวาร เทพธร', category: 'fresh', duration: '7:55 ชม.' },
  { id: '3', title: 'Snowwhite Note', category: 'posture', duration: '7:55 ชม.' },
  { id: '4', title: 'Moonlight Sleep', category: 'helper', duration: '6:30 ชม.' },
];

export default function PostSleepScreen() {
  const router = useRouter();

  const renderCategory = (categoryKey: string) => {
    const filteredPosts = posts.filter(p => p.category === categoryKey);

    return (
      <View key={categoryKey} style={styles.categorySection}>
        <Text style={styles.categoryTitle}>{getCategoryTitle(categoryKey)}</Text>
        {filteredPosts.length === 0 ? (
          <Text style={styles.emptyText}>ยังไม่มีโพสต์ในหมวดนี้</Text>
        ) : (
          filteredPosts.map(post => (
            <View key={post.id} style={styles.postCard}>
              <Text style={styles.postTitle}>{post.title}</Text>
              <Text style={styles.postDetail}>ระยะเวลา: {post.duration}</Text>
            </View>
          ))
        )}
      </View>
    );
  };

  const getCategoryTitle = (key: string) => {
    const found = categories.find(c => c.key === key);
    return found?.title || 'ไม่ทราบหมวด';
  };
  
  return (
    <View style={styles.container}>
      <Text style={styles.header}>โพสต์แนะนำการนอน</Text>

      <FlatList
        data={categories}
        keyExtractor={item => item.key}
        renderItem={({ item }) => renderCategory(item.key)}
        contentContainerStyle={{ paddingBottom: 20 }}
      />

      <TouchableOpacity style={styles.addButton} onPress={() => router.push('/(sleep)/addguide')}>
        <Text style={styles.addButtonText}>เพิ่ม GuideSleep</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20 },
  header: { fontSize: 22, fontWeight: 'bold', marginBottom: 10 },
  categorySection: { marginBottom: 20 },
  categoryTitle: { fontSize: 18, fontWeight: '600', marginBottom: 8 },
  postCard: {
    backgroundColor: '#f9f9f9',
    padding: 12,
    borderRadius: 8,
    marginBottom: 6,
    borderWidth: 1,
    borderColor: '#ddd',
  },
  postTitle: { fontSize: 16, fontWeight: '500' },
  postDetail: { fontSize: 14, color: '#555' },
  emptyText: { fontSize: 14, color: '#999', fontStyle: 'italic' },
  addButton: {
    backgroundColor: '#007AFF',
    padding: 12,
    borderRadius: 8,
    alignItems: 'center',
    marginTop: 10,
  },
  addButtonText: { color: '#fff', fontSize: 16 },
});
