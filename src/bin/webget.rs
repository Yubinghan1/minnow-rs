use std::env;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message)
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let hostname = args
        .next()
        .ok_or_else(|| invalid_input("Usage:webget <hostname> <path>"))?;
    let path = args
        .next()
        .ok_or_else(|| invalid_input("Usage:webget <hostname> <path>"))?;
    if args.next().is_some() {
        return Err(invalid_input("Usage:webget <hostname> <path>"));
    }

    if !path.starts_with('/') {
        return Err(invalid_input("The path must begin with '/"));
    }

    let address = format!("{}:80", hostname);

    let mut stream = TcpStream::connect(&address)?;

    let request = format!(
        "GET {path} HTTP/1.1\r\n
        Host: {hostname}\r\n
        Connection: close\r\n
        \r\n"
    );

    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut buffer = [0u8; 8192];
    let mut stdout = io::stdout().lock();

    loop {
        let byte_read = stream.read(&mut buffer)?;
        if byte_read == 0 {
            break;
        }
        stdout.write_all(&buffer[..byte_read])?;
    }

    stdout.flush()?;
    Ok(())
}
