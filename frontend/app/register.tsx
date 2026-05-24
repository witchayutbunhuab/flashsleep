import * as ImagePicker from 'expo-image-picker';
import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ScrollView,
  Image,
  Platform,
} from 'react-native';
import { useRouter } from 'expo-router';
// 📌 นำเข้า DateTimePicker
import DateTimePicker from '@react-native-community/datetimepicker'; 
import axios from '../src/config/axiosInstance';

export default function RegisterScreen() {
  const router = useRouter();

  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [gender, setGender] = useState('');
  const [birthdate, setBirthdate] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [profileImage, setProfileImage] = useState<string | null>(null);

  // 📌 เพิ่ม State สำหรับจัดการ Date Picker
  const [date, setDate] = useState(new Date());
  const [showDatePicker, setShowDatePicker] = useState(false);

  const pickImage = async () => {
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ImagePicker.MediaTypeOptions.Images,
      allowsEditing: true,
      aspect: [1, 1],
      quality: 1,
    });

    if (!result.canceled) {
      setProfileImage(result.assets[0].uri);
    }
  };

  // 📌 ฟังก์ชันจัดการเมื่อผู้ใช้เลือกวันที่
  const onChangeDate = (event: any, selectedDate?: Date) => {
    // ถ้าเป็น Android ให้ซ่อนปฏิทินทันทีที่เลือกเสร็จ
    if (Platform.OS === 'android') {
      setShowDatePicker(false);
    }
    
    if (selectedDate) {
      setDate(selectedDate);
      // แปลงวันที่เป็น YYYY-MM-DD สำหรับส่งให้ Backend
      const formattedDate = selectedDate.toISOString().split('T')[0];
      setBirthdate(formattedDate);
    }
  };

  const handleRegister = async () => {
    if (
      !firstName ||
      !lastName ||
      !gender ||
      !birthdate ||
      !email ||
      !password ||
      !confirmPassword
    ) {
      Alert.alert('ข้อผิดพลาด', 'กรุณากรอกข้อมูลให้ครบทุกช่อง');
      return;
    }

    if (password !== confirmPassword) {
      Alert.alert('ข้อผิดพลาด', 'รหัสผ่านไม่ตรงกัน');
      return;
    }

    try {
      const formData = new FormData();
      formData.append('first_name', firstName);
      formData.append('last_name', lastName);
      formData.append('gender', gender);
      formData.append('birthdate', birthdate);
      formData.append('email', email);
      formData.append('password', password);

      if (profileImage) {
        const localUri = profileImage;
        const filename = localUri.split('/').pop() || 'profile.jpg';
        const match = /\.(\w+)$/.exec(filename);
        const type = match ? `image/${match[1]}` : `image/jpeg`;

        formData.append('profile_image', {
          uri: localUri,
          name: filename,
          type,
        } as any);
      }

      const response = await axios.post('/register', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      Alert.alert('สำเร็จ', 'สมัครสมาชิกเรียบร้อยแล้ว');
      router.push('/login');
      
    } catch (error: any) {
      console.log('Register error:', error.response?.data || error.message);
      const errorMessage =
        error.response?.data?.detail || 'การสมัครสมาชิกล้มเหลว';
      Alert.alert('ข้อผิดพลาด', errorMessage);
    }
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>สมัครสมาชิก</Text>

      <TouchableOpacity onPress={pickImage} style={styles.imagePicker}>
        {profileImage ? (
          <Image source={{ uri: profileImage }} style={styles.image} />
        ) : (
          <Text style={styles.imagePlaceholder}>เลือกรูปโปรไฟล์</Text>
        )}
      </TouchableOpacity>

      <TextInput style={styles.input} placeholder="ชื่อ" value={firstName} onChangeText={setFirstName} />
      <TextInput style={styles.input} placeholder="นามสกุล" value={lastName} onChangeText={setLastName} />
      <TextInput style={styles.input} placeholder="เพศ (Male, Female, Other)" value={gender} onChangeText={setGender} />

      {/* 📌 เปลี่ยนช่องวันเกิดเป็นปุ่มกด */}
      <TouchableOpacity 
        style={styles.dateInput} 
        onPress={() => setShowDatePicker(true)}
      >
        <Text style={birthdate ? styles.dateText : styles.placeholderText}>
          {birthdate ? `วันเกิด: ${birthdate}` : 'เลือกวันเกิด (YYYY-MM-DD)'}
        </Text>
      </TouchableOpacity>

      {/* 📌 Component ปฏิทินที่จะโผล่มาตอนกดปุ่ม */}
      {showDatePicker && (
        <DateTimePicker
          value={date}
          mode="date"
          display="default"
          maximumDate={new Date()} // ป้องกันไม่ให้เลือกวันเกิดในอนาคต
          onChange={onChangeDate}
        />
      )}

      <TextInput style={styles.input} placeholder="อีเมล" value={email} onChangeText={setEmail} autoCapitalize="none" keyboardType="email-address" />
      <TextInput style={styles.input} placeholder="รหัสผ่าน" value={password} onChangeText={setPassword} secureTextEntry />
      <TextInput style={styles.input} placeholder="ยืนยันรหัสผ่าน" value={confirmPassword} onChangeText={setConfirmPassword} secureTextEntry />

      <TouchableOpacity style={styles.button} onPress={handleRegister}>
        <Text style={styles.buttonText}>สมัครสมาชิก</Text>
      </TouchableOpacity>

      <TouchableOpacity onPress={() => router.push('/login')}>
        <Text style={styles.registerText}>มีบัญชีอยู่แล้วเข้า ล็อกอิน</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: 20, backgroundColor: '#fff', flexGrow: 1, justifyContent: 'center' },
  title: { fontSize: 28, fontWeight: 'bold', marginBottom: 20, textAlign: 'center' },
  input: { borderWidth: 1, borderColor: '#ccc', borderRadius: 8, padding: 10, marginBottom: 15 },
  
  // 📌 เพิ่ม Styles สำหรับช่องวันเกิด
  dateInput: {
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 8,
    padding: 12,
    marginBottom: 15,
    justifyContent: 'center',
    backgroundColor: '#fff',
  },
  dateText: { color: '#000', fontSize: 14 },
  placeholderText: { color: '#999', fontSize: 14 },

  button: { backgroundColor: '#2196F3', padding: 15, borderRadius: 8 },
  buttonText: { color: '#fff', textAlign: 'center', fontWeight: 'bold' },
  registerText: { color: '#2196F3', textAlign: 'center', marginTop: 15 },
  imagePicker: { alignItems: 'center', marginBottom: 20 },
  imagePlaceholder: { width: 120, height: 120, borderRadius: 60, backgroundColor: '#eee', textAlign: 'center', lineHeight: 120, color: '#aaa' },
  image: { width: 120, height: 120, borderRadius: 60 },
});
