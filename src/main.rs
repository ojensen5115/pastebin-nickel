#[macro_use] extern crate nickel;

use nickel::Nickel;
use nickel::{Request, Response, MiddlewareResult, StaticFilesHandler};
use nickel::status::StatusCode;

use nickel::HttpRouter;
use nickel::mimes::MediaType;
use nickel::Responder;

extern crate formdata;


extern crate chrono;
extern crate crypto;
#[macro_use] extern crate lazy_static;
extern crate rand;
extern crate syntect;

extern crate hyper;
use hyper::header::UserAgent;

use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::io::Write;
use std::io::Read;
use std::thread;
use std::time;

use chrono::{DateTime, UTC};

use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;

use rand::Rng;

use syntect::easy::HighlightLines;
use syntect::highlighting::{Theme, ThemeSet, Style};
use syntect::html::highlighted_snippet_for_string;
use syntect::parsing::SyntaxSet;
use syntect::util::as_24_bit_terminal_escaped;

const SOCKET: &'static str = "0.0.0.0:6767";
const BASE62: &'static [u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ID_LEN: usize = 5;
const KEY_BYTES: usize = 8;
const MAX_PASTE_BYTES: usize = 2 * 1024 * 1024; // 2 MB

lazy_static! {
    static ref HMAC_KEY: String = {
        let mut file = match File::open("hmac_key.txt") {
            Ok(f) => f,
            Err(_) => return String::new()
        };
        let mut key = String::new();
        file.read_to_string(&mut key).expect("reading HMAC key file");
        key
    };

    static ref HL_THEME: Theme = {
        let ts = ThemeSet::load_defaults();
        let theme = &ts.themes["base16-eighties.dark"];
        theme.clone()
    };
}

// SyntaxSet does not implement Copy/Sync, so we do it like this.
// see https://github.com/trishume/syntect/issues/20
thread_local! {
    static SYNTAX_SET: SyntaxSet = SyntaxSet::load_defaults_nonewlines();
}

#[derive(Debug)]
enum HighlightedText {
    Terminal(String),
    Html(String),
    Error(String)
}



fn main() {
    if HMAC_KEY.as_bytes().len() == 0 {
        println!("You must set a key in hmac_key.txt");
        std::process::exit(1);
    }

    let mut server = Nickel::new();
    let mut router = Nickel::router();
    router.get("/", usage);
    router.post("/", submit);
    router.get("/:pasteid", retrieve);
    router.get("/:pasteid/:lang", retrieve);
    router.delete("/:pasteid", delete);
    router.delete("/:pasteid/:key", delete);
    router.put("/:pasteid/", replace);
    router.put("/:pasteid/:key", replace);

    server.utilize(middleware! { |req|
        let utc: DateTime<UTC> = UTC::now();
        println!("[{}] [{}]: {}", req.origin.remote_addr, utc.format("%Y-%m-%d %H:%M:%S"), req.origin.uri);
    });


    // mimetype inferred from extension
    // TODO: how to serve static html without ending the URL in .html?
    server.utilize(StaticFilesHandler::new("./static"));

    server.utilize(router);
    // TODO: figure out how to make middleware run after the handler
    /*
    server.utilize(middleware! {|_, resp|
        println!("response generated");
    });
    */

    // every day, delete pastes > 30 days old
    thread::spawn(move || {
        let one_day = time::Duration::from_secs(60*60*24);
        let thirty_days = one_day * 30;
        println!("Pastes are deleted when they are 30 days old.");
        loop {
            let now = time::SystemTime::now();
            let files = fs::read_dir("./uploads").unwrap();
            for file in files {
                let path = file.unwrap().path();
                let attr = fs::metadata(&path).unwrap();
                let last_modified = attr.modified().expect("reading last modified time");
                if now.duration_since(last_modified).unwrap() > thirty_days {
                    fs::remove_file(path).expect("deleting file");
                }
            }
            thread::sleep(one_day);
        }
        });

    // in Nickel, this seems to be blocking, so it has to be last
    server.listen(SOCKET).expect("Failed to launch server");

}

// TODO: why do we need the two different "mut"s in the params?
fn usage<'a>(_: &mut Request, mut res: Response<'a>) -> MiddlewareResult<'a> {
    let mut data = HashMap::new();
    data.insert("socket", SOCKET);
    data.insert("id", "vxcRz");
    data.insert("key", "a7772362cf6e2c36");
    data.insert("ext", "rs");
    res.set(MediaType::Txt);
    res.render("templates/index.hbs", &data)
}

fn submit<'a>(req: &mut Request, mut res: Response<'a>) -> MiddlewareResult<'a> {
    // content-type is plaintext
    res.set(MediaType::Txt);
    // ready raw post into vector of bytes (supports non-UTF8)
    let mut raw_body = vec![];
    req.origin.read_to_end(&mut raw_body).unwrap();
    // read bytes into UTF8 string
    let body = match String::from_utf8(raw_body) {
        Ok(s) => s,
        _ => return (StatusCode::BadRequest, "Invalid paste data submitted: non-UTF8").respond(res)
    };

    // grab the paste from formdata or raw post
    let paste = match formdata::read_formdata(&mut body.as_bytes(), &req.origin.headers) {
        Ok(data) => {
            /*
            // TODO: why doesn't this work?
            for (name, value) in data.fields {
                if name == "data" {
                    value
                }
            }
            return (StatusCode::BadRequest, "Invalid paste data submitted: invalid form submitted").respond(res)
            */
            let mut x = None;
            for (name, value) in data.fields {
                if name == "data" {
                    x = Some(value);
                    break;
                }
            }
            match x {
                Some(s) => s,
                _ => return (StatusCode::BadRequest, "Invalid paste data submitted: invalid form submitted").respond(res)
            }
        },
        _ => body
    };

    // verify max size before saving it
    if paste.len() > MAX_PASTE_BYTES {
        return (StatusCode::BadRequest, format!("Pastes may not be more than {} MB.\n", MAX_PASTE_BYTES/1048576)).respond(res)
    }
    // get paste ID and URL
    let mut id: String;
    let mut path: String;
    let mut double_id_len = ID_LEN * 2; // so we increase by 1 every two loops
    loop {
        id = generate_id(double_id_len / 2);
        path = format!("uploads/{id}", id = id);
        if !Path::new(&path).exists() {
            break;
        }
        double_id_len += 1;
    }

    let url = format!("http://{socket}/{id}", socket = SOCKET, id = id);
    let mut f = File::create(path).expect("creating paste file");
    f.write_all(paste.as_bytes()).expect("writing paste file");
    res.set(MediaType::Txt);
    format!("View URL: {url}\nEdit URL: {url}/{key}\n", url = url, key = gen_key(&id)).respond(res)
}

fn retrieve<'a>(req: &mut Request, mut res: Response<'a>) -> MiddlewareResult<'a> {
    // content type defaults to plaintext
    res.set(MediaType::Txt);
    let id = req.param("pasteid").unwrap();
    let lang = req.param("lang");

    let mut f = match File::open(format!("uploads/{id}", id = id)) {
        Ok(f) => f,
        Err(_) => return (StatusCode::BadRequest, format!("Paste {} does not exist\n", id)).respond(res)
    };

    let mut buffer = String::new();
    f.read_to_string(&mut buffer).expect("reading paste file");

    match lang {
        Some(lang) => {
            // syntax highlighting
            let html_output = !is_curl(req);
            match highlight(buffer, lang, html_output) {
                HighlightedText::Terminal(s) => s.respond(res),
                HighlightedText::Html(s) => {
                    res.set(MediaType::Html);
                    let mut data = HashMap::new();
                    data.insert("paste", s);
                    res.render("templates/paste_html.hbs", &data)
                },
                HighlightedText::Error(s) => return (StatusCode::BadRequest, format!("Invalid request: {}\n", s)).respond(res)
            }
        },
        // no syntax highlighting
        None => {
            buffer.respond(res)
        }
    }
}

fn delete<'a>(req: &mut Request, mut res: Response<'a>) -> MiddlewareResult<'a> {
    res.set(MediaType::Txt);
    let (id, path) = match validate_key_id(req) {
        Ok((id, path)) => (id, path),
        Err(reason) => return (StatusCode::BadRequest, format!("Invalid request: {}.\n", reason)).respond(res)
    };
    // delete file
    fs::remove_file(path).expect("deleting paste");
    format!("Paste {} deleted.\n", id).respond(res)
}

fn replace<'a>(req: &mut Request, mut res: Response<'a>) -> MiddlewareResult<'a> {
    res.set(MediaType::Txt);
    let (id, path) = match validate_key_id(req) {
        Ok((id, path)) => (id, path),
        Err(reason) => return (StatusCode::BadRequest, format!("Invalid request: {}.\n", reason)).respond(res)
    };
    let mut raw_body = vec![];
    req.origin.read_to_end(&mut raw_body).unwrap();
    // read bytes into UTF8 string
    let paste = match String::from_utf8(raw_body) {
        Ok(s) => s,
        _ => return (StatusCode::BadRequest, "Invalid paste data submitted: non-UTF8").respond(res)
    };
    // verify max size before saving it
    if paste.len() > MAX_PASTE_BYTES {
        return (StatusCode::BadRequest, format!("Pastes may not be more than {} MB.\n", MAX_PASTE_BYTES/1048576)).respond(res)
    }
    let mut f = File::create(path).expect("creating file");
    f.write_all(paste.as_bytes()).expect("writing file");
    format!("http://{socket}/{id} overwritten.\n", socket=SOCKET, id = id).respond(res)
}





fn validate_key_id(req: &Request) -> Result<(String, String), String> {
    let id = req.param("pasteid").unwrap_or("");
    let key = req.param("key").unwrap_or("");
    let path = format!("uploads/{id}", id = id);
    if !Path::new(&path).exists() {
        return Err(format!("Paste {} does not exist", id));
    }
    if key == "" {
        return Err("No key supplied".to_string())
    }
    if key != gen_key(&id) {
        return Err("Key is not valid".to_string());
    }
    Ok((id.to_string(), path))
}

fn generate_id(size: usize) -> String {
    let mut id = String::with_capacity(size);
    let mut rng = rand::thread_rng();
    for _ in 0..size {
        id.push(BASE62[rng.gen::<usize>() % 62] as char);
    }
    id
}

fn gen_key(input: &str) -> String {
    let mut hmac = Hmac::new(Sha256::new(), HMAC_KEY.as_bytes());
    hmac.input(input.as_bytes());
    let hmac_result = hmac.result();
    let key: String = hmac_result.code().iter()
        .take(KEY_BYTES)
        .map(|b| format!("{:02X}", b))
        .collect();
    key.to_lowercase()
}


fn is_curl(req: &Request) -> bool {
    match req.origin.headers.get::<UserAgent>() {
        Some(&UserAgent(ref string)) => &string[..5] == "curl/",
        _ => true
    }
}

fn highlight(buffer: String, lang: &str, html: bool) -> HighlightedText {
    SYNTAX_SET.with(|ss| {
        let syntax = ss.find_syntax_by_extension(lang).unwrap_or_else(|| ss.find_syntax_plain_text());
        if syntax.name == "Plain Text" {
            return HighlightedText::Error(format!("Requested highlight \"{}\" not available", lang));
        }
        if html {
            HighlightedText::Html(highlighted_snippet_for_string(&buffer, syntax, &HL_THEME))
        } else {
            let mut highlighter = HighlightLines::new(syntax, &HL_THEME);
            let mut output = String::new();
            for line in buffer.lines() {
                let ranges: Vec<(Style, &str)> = highlighter.highlight(line);
                let escaped;
                escaped = as_24_bit_terminal_escaped(&ranges[..], false);
                output += &format!("{}\n", escaped);
            }
            HighlightedText::Terminal(output)
        }
    })
}
