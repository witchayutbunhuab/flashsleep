// ใน LoginScreen.js
import React, { useState } from 'react';
import { View, TextInput, Button } from 'react-native';

export default function LoginScreen({ navigation }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  return (
    <View>
      <TextInput placeholder="Email" onChangeText={setEmail} />
      <TextInput placeholder="Password" secureTextEntry onChangeText={setPassword} />
      <Button title="Login" onPress={() => { /* handle login */ }} />
      <Button
        title="Register"
        onPress={() => navigation.navigate('Register')}  // ไปหน้า Register
      />
    </View>
  );
}
