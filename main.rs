use std::time::Instant;

/// Реализация потокового шифра RC4 на Rust.
/// Оптимизированная версия с использованием арифметики u8 и in-place обработки.

pub struct Rc4 {
    s: [u8; 256], // Массив состояния (S-box)
    i: u8,        // Счетчик i (u8 обеспечивает автоматический mod 256)
    j: u8,        // Счетчик j (u8 обеспечивает автоматический mod 256)
}

impl Rc4 {
    /// Создает новый экземпляр RC4 и выполняет KSA (Key-Scheduling Algorithm).
    pub fn new(key: &[u8]) -> Self {
        if key.is_empty() || key.len() > 256 {
            panic!("Key length must be between 1 and 256 bytes");
        }

        let mut s = [0u8; 256];
        // Шаг 1: Заполнить массив S линейно
        for i in 0..=255 {
            s[i as usize] = i;
        }

        // Шаг 2: Перемешать массив S используя ключ
        let mut j: u8 = 0;
        // Используем usize для итерации, чтобы избежать бесконечного цикла при i=255 -> 0
        for i in 0..256 { 
            let key_byte = key[i % key.len()];
            
            // j = (j + S[i] + Key[i % key_length]) % 256;
            // wrapping_add используется для явного указания на переполнение
            j = j.wrapping_add(s[i]).wrapping_add(key_byte);
            
            s.swap(i, j as usize);
        }

        Rc4 { s, i: 0, j: 0 }
    }

    /// Основной метод шифрования/дешифрования (PRGA).
    /// Работает "на месте" (in-place) с переданным буфером, избегая аллокаций.
    /// Это наиболее производительный способ использования.
    pub fn process(&mut self, data: &mut [u8]) {
        // Кэшируем индексы в локальные переменные, чтобы избежать лишних обращений к self
        // внутри горячего цикла (хотя компилятор может это оптимизировать и сам).
        let mut i = self.i;
        let mut j = self.j;
        let s = &mut self.s;

        for byte in data.iter_mut() {
            // 1. i = (i + 1) % 256
            i = i.wrapping_add(1);

            // 2. j = (j + S[i]) % 256
            let si = s[i as usize];
            j = j.wrapping_add(si);

            // 3. swap(S[i], S[j])
            let sj = s[j as usize];
            s.swap(i as usize, j as usize);

            // 4. Получить байт гаммы K
            // t = (S[i] + S[j]) % 256
            let t = si.wrapping_add(sj);
            let k = s[t as usize];

            // 5. XOR с входным байтом
            *byte ^= k;
        }

        // Сохраняем состояние обратно
        self.i = i;
        self.j = j;
    }

    /// Обертка для удобства, если нужен новый Vec (как в предыдущей версии).
    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = data.to_vec(); // Аллокация здесь
        self.process(&mut output);
        output
    }
}

// Бенчмарки и пример использования
fn main() {
    // 1. Демонстрация
    let key = b"Key";
    let plaintext = b"Plaintext";
    
    let mut rc4 = Rc4::new(key);
    let ciphertext = rc4.apply(plaintext);
    
    println!("--- Demo ---");
    println!("Key: {:?}", String::from_utf8_lossy(key));
    println!("Plaintext: {:?}", String::from_utf8_lossy(plaintext));
    println!("Ciphertext (Hex): {:02X?}", ciphertext);

    // 2. Бенчмарк
    println!("\n--- Benchmark ---");
    let size_mb = 100;
    let size_bytes = size_mb * 1024 * 1024;
    let mut buffer = vec![0u8; size_bytes];
    let mut rc4_bench = Rc4::new(b"BenchmarkKey");

    println!("Encrypting {} MB...", size_mb);
    let start = Instant::now();
    
    // Используем in-place метод process
    rc4_bench.process(&mut buffer);
    
    let duration = start.elapsed();
    let seconds = duration.as_secs_f64();
    let speed_mb_s = (size_mb as f64) / seconds;

    println!("Time: {:.4} seconds", seconds);
    println!("Speed: {:.2} MB/s", speed_mb_s);
    
    // Проверка, что работа действительно была выполнена (prevent optimizer elimination)
    println!("First byte of encrypted data: {:02X}", buffer[0]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test Vector 1
    #[test]
    fn test_vector_1() {
        let key = b"Key"; 
        let plaintext = b"Plaintext";
        let expected_ciphertext: [u8; 9] = [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3];

        let mut rc4 = Rc4::new(key);
        let result = rc4.apply(plaintext);
        assert_eq!(result, expected_ciphertext);
    }

    /// Test Vector 2
    #[test]
    fn test_vector_2() {
        let key = b"Wiki"; 
        let plaintext = b"pedia";
        let expected_ciphertext: [u8; 5] = [0x10, 0x21, 0xBF, 0x04, 0x20];

        let mut rc4 = Rc4::new(key);
        let result = rc4.apply(plaintext);
        assert_eq!(result, expected_ciphertext);
    }

    /// Проверка симметричности
    #[test]
    fn test_symmetry() {
        let key = b"SecretKey";
        let plaintext = b"Hello, World!";
        
        let mut rc4_enc = Rc4::new(key);
        let ciphertext = rc4_enc.apply(plaintext);
        
        let mut rc4_dec = Rc4::new(key);
        // Дешифруем in-place для разнообразия
        let mut decrypted = ciphertext.clone();
        rc4_dec.process(&mut decrypted);

        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
