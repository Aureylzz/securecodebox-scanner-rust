use std::ptr;

fn main() {
    println!("Security scanner demo crate");
    
    // Unsafe code that will trigger cargo-geiger
    unsafe {
        // Raw pointer dereference
        let x = 42;
        let raw_ptr = &x as *const i32;
        let _value = *raw_ptr;
        
        // Unsafe memory manipulation
        let mut vec = vec![1, 2, 3];
        let ptr = vec.as_mut_ptr();
        ptr::write(ptr.offset(1), 99);
    }
    
    // Using the vulnerable dependencies
    let _now = chrono::Utc::now();
    let _re = regex::Regex::new(r"\d+").unwrap();
    
    println!("Program completed");
}

// More unsafe code for cargo-geiger
unsafe fn dangerous_function(ptr: *const u8) -> u8 {
    *ptr
}

// Unsafe trait implementation
unsafe trait UnsafeTrait {
    fn do_something(&self);
}

unsafe impl UnsafeTrait for i32 {
    fn do_something(&self) {
        println!("Unsafe trait impl: {}", self);
    }
}