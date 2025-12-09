/// Реализация потокового шифра RC4 на Rust.
/// Основано на TODO листе и спецификациях.

pub struct Rc4 {
    s: [u8; 256], // Массив состояния (S-box)
    i: usize,     // Счетчик i
    j: usize,     // Счетчик j
}

impl Rc4 {
    /// Создает новый экземпляр RC4 и выполняет KSA (Key-Scheduling Algorithm).
    ///
    /// # Аргументы
    /// * `key` - Ключ шифрования (от 1 до 256 байт).
    pub fn new(key: &[u8]) -> Self {
        if key.is_empty() || key.len() > 256 {
            panic!("Key length must be between 1 and 256 bytes");
        }

        // 1.1. Подготовка структур данных
        let mut s = [0u8; 256];
        
        // 1.2. Алгоритм KSA
        
        // Шаг 1: Заполнить массив S линейно
        for i in 0..256 {
            s[i] = i as u8;
        }

        // Шаг 2: Перемешать массив S используя ключ
        let mut j: usize = 0;
        for i in 0..256 {
            // j = (j + S[i] + Key[i % key_length]) % 256;
            let key_byte = key[i % key.len()] as usize;
            j = (j + s[i] as usize + key_byte) % 256;
            
            s.swap(i, j); // swap(S[i], S[j])
        }

        // 1.3. Подготовка к PRGA (сброс счетчиков)
        Rc4 { s, i: 0, j: 0 }
    }

    /// Шифрует или расшифровывает данные (операция симметрична).
    /// Реализует алгоритм PRGA (Pseudo-Random Generation Algorithm).
    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());

        // 1.3. Алгоритм PRGA
        for &input_byte in data {
            // 1. i = (i + 1) % 256
            self.i = (self.i + 1) % 256;

            // 2. j = (j + S[i]) % 256
            self.j = (self.j + self.s[self.i] as usize) % 256;

            // 3. swap(S[i], S[j])
            self.s.swap(self.i, self.j);

            // 4. Получить байт гаммы K
            // t = (S[i] + S[j]) % 256
            let t = (self.s[self.i] as usize + self.s[self.j] as usize) % 256;
            let k = self.s[t];

            // 5. Зашифровать байт: OutputByte = InputByte XOR K
            output.push(input_byte ^ k);
        }

        output
    }
}

// Пример использования в main (не обязателен для тестов, но полезен для демонстрации)
fn main() {
    let key = b"Key";
    let plaintext = b"Plaintext";
    
    let mut rc4 = Rc4::new(key);
    let ciphertext = rc4.apply(plaintext);
    
    println!("Key: {:?}", String::from_utf8_lossy(key));
    println!("Plaintext: {:?}", String::from_utf8_lossy(plaintext));
    println!("Ciphertext (Hex): {:02X?}", ciphertext);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1.4. Тестовые векторы RC4 (Проверка) - Test Vector 1
    #[test]
    fn test_vector_1() {
        // Key: Key (ASCII) -> 4B 65 79
        let key = b"Key"; 
        
        // Plaintext: Plaintext (ASCII) -> 50 6C 61 69 6E 74 65 78 74
        let plaintext = b"Plaintext";
        
        // Ciphertext: BB F3 16 E8 D9 40 AF 0A D3
        let expected_ciphertext: [u8; 9] = [
            0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3
        ];

        let mut rc4 = Rc4::new(key);
        let result = rc4.apply(plaintext);

        assert_eq!(result, expected_ciphertext, "Test Vector 1 failed");
    }

    /// 1.4. Тестовые векторы RC4 (Проверка) - Test Vector 2
    #[test]
    fn test_vector_2() {
        // Key: Wiki (ASCII) -> 57 69 6B 69
        let key = b"Wiki"; 
        
        // Plaintext: pedia (ASCII) -> 70 65 64 69 61
        let plaintext = b"pedia";
        
        // Ciphertext: 10 21 BF 04 20
        let expected_ciphertext: [u8; 5] = [
            0x10, 0x21, 0xBF, 0x04, 0x20
        ];

        let mut rc4 = Rc4::new(key);
        let result = rc4.apply(plaintext);

        assert_eq!(result, expected_ciphertext, "Test Vector 2 failed");
    }

    /// Проверка свойства симметричности (Шифрование -> Расшифрование = Исходный текст)
    #[test]
    fn test_symmetry() {
        let key = b"SecretKey";
        let plaintext = b"Hello, World!";
        
        // Шифруем
        let mut rc4_enc = Rc4::new(key);
        let ciphertext = rc4_enc.apply(plaintext);
        
        // Расшифровываем (создаем новый экземпляр с тем же ключом)
        let mut rc4_dec = Rc4::new(key);
        let decrypted = rc4_dec.apply(&ciphertext);

        assert_eq!(plaintext.to_vec(), decrypted, "Decryption should return original plaintext");
    }
}