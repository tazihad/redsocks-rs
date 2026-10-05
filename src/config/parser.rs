use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Ident(String),
    StringLit(String),
    OpenBrace,
    CloseBrace,
    Equals,
    Semicolon,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Lexer error at line {line}, col {col}: {message}")]
    Lexer {
        line: usize,
        col: usize,
        message: String,
    },
    #[error("Parser error at line {line}, col {col}: {message}")]
    Parser {
        line: usize,
        col: usize,
        message: String,
    },
}

pub struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    line: usize,
    col: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            chars: input.char_indices().peekable(),
            line: 1,
            col: 1,
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.chars.peek().map(|&(_, c)| c)
    }

    fn advance(&mut self) -> Option<char> {
        if let Some((_, c)) = self.chars.next() {
            if c == '\n' {
                self.line += 1;
                self.col = 1;
            } else {
                self.col += 1;
            }
            Some(c)
        } else {
            None
        }
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, ParseError> {
        let mut tokens = Vec::new();

        while let Some(c) = self.peek() {
            let start_line = self.line;
            let start_col = self.col;

            if c.is_whitespace() {
                self.advance();
                continue;
            }

            // Comments
            if c == '/' {
                self.advance();
                match self.peek() {
                    Some('/') => {
                        self.advance();
                        // Line comment: consume until newline
                        while let Some(ch) = self.peek() {
                            self.advance();
                            if ch == '\n' {
                                break;
                            }
                        }
                        continue;
                    }
                    Some('*') => {
                        self.advance();
                        // Block comment: consume until */
                        let mut closed = false;
                        while let Some(ch) = self.advance() {
                            if ch == '*' && self.peek() == Some('/') {
                                self.advance();
                                closed = true;
                                break;
                            }
                        }
                        if !closed {
                            return Err(ParseError::Lexer {
                                line: start_line,
                                col: start_col,
                                message: "Unterminated block comment".to_string(),
                            });
                        }
                        continue;
                    }
                    _ => {
                        return Err(ParseError::Lexer {
                            line: start_line,
                            col: start_col,
                            message: "Unexpected character '/'".to_string(),
                        });
                    }
                }
            }

            match c {
                '{' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::OpenBrace,
                        line: start_line,
                        col: start_col,
                    });
                }
                '}' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::CloseBrace,
                        line: start_line,
                        col: start_col,
                    });
                }
                '=' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Equals,
                        line: start_line,
                        col: start_col,
                    });
                }
                ';' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Semicolon,
                        line: start_line,
                        col: start_col,
                    });
                }
                '"' => {
                    self.advance(); // consume opening quote
                    let mut s = String::new();
                    let mut closed = false;
                    while let Some(ch) = self.advance() {
                        if ch == '"' {
                            closed = true;
                            break;
                        } else if ch == '\\' {
                            match self.advance() {
                                Some('n') => s.push('\n'),
                                Some('t') => s.push('\t'),
                                Some('r') => s.push('\r'),
                                Some('\\') => s.push('\\'),
                                Some('\'') => s.push('\''),
                                Some('"') => s.push('"'),
                                Some(other) => {
                                    return Err(ParseError::Lexer {
                                        line: self.line,
                                        col: self.col,
                                        message: format!("Unknown escape character: \\{}", other),
                                    });
                                }
                                None => {
                                    return Err(ParseError::Lexer {
                                        line: start_line,
                                        col: start_col,
                                        message: "Unterminated escape sequence in string literal"
                                            .to_string(),
                                    });
                                }
                            }
                        } else {
                            s.push(ch);
                        }
                    }
                    if !closed {
                        return Err(ParseError::Lexer {
                            line: start_line,
                            col: start_col,
                            message: "Unterminated string literal".to_string(),
                        });
                    }
                    tokens.push(Token {
                        kind: TokenKind::StringLit(s),
                        line: start_line,
                        col: start_col,
                    });
                }
                _ => {
                    // Identifier or unquoted word (letters, digits, '.', '-', ':', '_', '/')
                    let mut ident = String::new();
                    while let Some(ch) = self.peek() {
                        if ch.is_alphanumeric() || ch == '.' || ch == '-' || ch == '_' || ch == ':'
                        {
                            ident.push(ch);
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    if ident.is_empty() {
                        return Err(ParseError::Lexer {
                            line: start_line,
                            col: start_col,
                            message: format!("Unexpected character: {:?}", c),
                        });
                    }
                    tokens.push(Token {
                        kind: TokenKind::Ident(ident),
                        line: start_line,
                        col: start_col,
                    });
                }
            }
        }

        Ok(tokens)
    }
}

pub struct ConfigParser;

impl ConfigParser {
    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<AppConfig, ParseError> {
        let content = std::fs::read_to_string(path)?;
        Self::parse_str(&content)
    }

    pub fn parse_str(content: &str) -> Result<AppConfig, ParseError> {
        let mut lexer = Lexer::new(content);
        let tokens = lexer.tokenize()?;
        let mut cursor = 0;
        let mut config = AppConfig::default();

        while cursor < tokens.len() {
            let section_tok = match &tokens[cursor].kind {
                TokenKind::Ident(name) => name.clone(),
                _ => {
                    return Err(ParseError::Parser {
                        line: tokens[cursor].line,
                        col: tokens[cursor].col,
                        message: format!("Expected section name, found {:?}", tokens[cursor].kind),
                    });
                }
            };
            cursor += 1;

            if cursor >= tokens.len() || tokens[cursor].kind != TokenKind::OpenBrace {
                let (line, col) = if cursor < tokens.len() {
                    (tokens[cursor].line, tokens[cursor].col)
                } else {
                    (tokens[cursor - 1].line, tokens[cursor - 1].col)
                };
                return Err(ParseError::Parser {
                    line,
                    col,
                    message: format!("Expected '{{' after section '{}'", section_tok),
                });
            }
            cursor += 1; // skip '{'

            // Parse key-value statements inside block
            let mut entries: Vec<(String, String, usize, usize)> = Vec::new();
            while cursor < tokens.len() && tokens[cursor].kind != TokenKind::CloseBrace {
                let (key, k_line, k_col) = match &tokens[cursor].kind {
                    TokenKind::Ident(k) => (k.clone(), tokens[cursor].line, tokens[cursor].col),
                    _ => {
                        return Err(ParseError::Parser {
                            line: tokens[cursor].line,
                            col: tokens[cursor].col,
                            message: format!("Expected key name, found {:?}", tokens[cursor].kind),
                        });
                    }
                };
                cursor += 1;

                if cursor >= tokens.len() || tokens[cursor].kind != TokenKind::Equals {
                    let (line, col) = if cursor < tokens.len() {
                        (tokens[cursor].line, tokens[cursor].col)
                    } else {
                        (tokens[cursor - 1].line, tokens[cursor - 1].col)
                    };
                    return Err(ParseError::Parser {
                        line,
                        col,
                        message: format!("Expected '=' after key '{}'", key),
                    });
                }
                cursor += 1;

                if cursor >= tokens.len() {
                    return Err(ParseError::Parser {
                        line: k_line,
                        col: k_col,
                        message: format!("Expected value for key '{}'", key),
                    });
                }

                let val = match &tokens[cursor].kind {
                    TokenKind::Ident(v) | TokenKind::StringLit(v) => v.clone(),
                    _ => {
                        return Err(ParseError::Parser {
                            line: tokens[cursor].line,
                            col: tokens[cursor].col,
                            message: format!("Expected value, found {:?}", tokens[cursor].kind),
                        });
                    }
                };
                cursor += 1;

                if cursor >= tokens.len() || tokens[cursor].kind != TokenKind::Semicolon {
                    let (line, col) = if cursor < tokens.len() {
                        (tokens[cursor].line, tokens[cursor].col)
                    } else {
                        (tokens[cursor - 1].line, tokens[cursor - 1].col)
                    };
                    return Err(ParseError::Parser {
                        line,
                        col,
                        message: format!("Expected ';' after statement '{} = {}'", key, val),
                    });
                }
                cursor += 1;

                entries.push((key, val, k_line, k_col));
            }

            if cursor >= tokens.len() || tokens[cursor].kind != TokenKind::CloseBrace {
                return Err(ParseError::Parser {
                    line: tokens.last().map(|t| t.line).unwrap_or(1),
                    col: tokens.last().map(|t| t.col).unwrap_or(1),
                    message: format!("Expected '}}' closing section '{}'", section_tok),
                });
            }
            cursor += 1; // skip '}'

            match section_tok.as_str() {
                "base" => {
                    Self::populate_base(&mut config.base, entries)?;
                }
                "redsocks" => {
                    let mut s = RedsocksConfig::default();
                    Self::populate_redsocks(&mut s, entries)?;
                    config.redsocks.push(s);
                }
                "redudp" => {
                    let mut s = RedudpConfig::default();
                    Self::populate_redudp(&mut s, entries)?;
                    config.redudp.push(s);
                }
                "dnstc" => {
                    let mut s = DnstcConfig::default();
                    Self::populate_dnstc(&mut s, entries)?;
                    config.dnstc.push(s);
                }
                "dnsu2t" => {
                    let mut s = Dnsu2tConfig::default();
                    Self::populate_dnsu2t(&mut s, entries)?;
                    config.dnsu2t.push(s);
                }
                other => {
                    return Err(ParseError::Parser {
                        line: tokens[cursor - 1].line,
                        col: tokens[cursor - 1].col,
                        message: format!("Unknown configuration section '{}'", other),
                    });
                }
            }
        }

        Ok(config)
    }

    fn parse_bool(val: &str, line: usize, col: usize) -> Result<bool, ParseError> {
        match val.to_ascii_lowercase().as_str() {
            "on" | "true" | "yes" | "1" => Ok(true),
            "off" | "false" | "no" | "0" => Ok(false),
            _ => Err(ParseError::Parser {
                line,
                col,
                message: format!("Invalid boolean value: '{}' (expected on/off)", val),
            }),
        }
    }

    fn parse_u16(val: &str, line: usize, col: usize) -> Result<u16, ParseError> {
        val.parse::<u16>().map_err(|e| ParseError::Parser {
            line,
            col,
            message: format!("Invalid u16 number '{}': {}", val, e),
        })
    }

    fn parse_u32(val: &str, line: usize, col: usize) -> Result<u32, ParseError> {
        val.parse::<u32>().map_err(|e| ParseError::Parser {
            line,
            col,
            message: format!("Invalid u32 number '{}': {}", val, e),
        })
    }

    fn parse_u64(val: &str, line: usize, col: usize) -> Result<u64, ParseError> {
        val.parse::<u64>().map_err(|e| ParseError::Parser {
            line,
            col,
            message: format!("Invalid u64 number '{}': {}", val, e),
        })
    }

    fn parse_usize(val: &str, line: usize, col: usize) -> Result<usize, ParseError> {
        val.parse::<usize>().map_err(|e| ParseError::Parser {
            line,
            col,
            message: format!("Invalid usize number '{}': {}", val, e),
        })
    }

    fn parse_ip(val: &str, line: usize, col: usize) -> Result<IpAddr, ParseError> {
        IpAddr::from_str(val).map_err(|e| ParseError::Parser {
            line,
            col,
            message: format!("Invalid IP address '{}': {}", val, e),
        })
    }

    fn populate_base(
        base: &mut BaseConfig,
        entries: Vec<(String, String, usize, usize)>,
    ) -> Result<(), ParseError> {
        for (k, v, line, col) in entries {
            match k.as_str() {
                "log_debug" => base.log_debug = Self::parse_bool(&v, line, col)?,
                "log_info" => base.log_info = Self::parse_bool(&v, line, col)?,
                "log" => base.log = v,
                "daemon" => base.daemon = Self::parse_bool(&v, line, col)?,
                "user" => base.user = Some(v),
                "group" => base.group = Some(v),
                "chroot" => base.chroot = Some(v),
                "redirector" => base.redirector = v,
                "tcp_keepalive_time" => base.tcp_keepalive_time = Self::parse_u32(&v, line, col)?,
                "tcp_keepalive_probes" => {
                    base.tcp_keepalive_probes = Self::parse_u32(&v, line, col)?
                }
                "tcp_keepalive_intvl" => base.tcp_keepalive_intvl = Self::parse_u32(&v, line, col)?,
                "rlimit_nofile" => base.rlimit_nofile = Self::parse_u64(&v, line, col)?,
                "redsocks_conn_max" => base.redsocks_conn_max = Self::parse_u32(&v, line, col)?,
                "connpres_idle_timeout" => {
                    base.connpres_idle_timeout = Self::parse_u64(&v, line, col)?
                }
                "max_accept_backoff" => base.max_accept_backoff = Self::parse_u64(&v, line, col)?,
                other => {
                    return Err(ParseError::Parser {
                        line,
                        col,
                        message: format!("Unknown key '{}' in base section", other),
                    });
                }
            }
        }
        Ok(())
    }

    fn populate_redsocks(
        cfg: &mut RedsocksConfig,
        entries: Vec<(String, String, usize, usize)>,
    ) -> Result<(), ParseError> {
        for (k, v, line, col) in entries {
            match k.as_str() {
                "local_ip" => cfg.local_ip = Self::parse_ip(&v, line, col)?,
                "local_port" => cfg.local_port = Self::parse_u16(&v, line, col)?,
                "listenq" => cfg.listenq = Self::parse_u32(&v, line, col)?,
                "splice" => cfg.splice = Self::parse_bool(&v, line, col)?,
                "ip" => cfg.ip = v,
                "port" => cfg.port = Self::parse_u16(&v, line, col)?,
                "type" => {
                    cfg.proxy_type = ProxyType::from_str(&v).map_err(|e| ParseError::Parser {
                        line,
                        col,
                        message: e,
                    })?
                }
                "login" => cfg.login = Some(v),
                "password" => cfg.password = Some(v),
                "disclose_src" => {
                    cfg.disclose_src =
                        DiscloseSrc::from_str(&v).map_err(|e| ParseError::Parser {
                            line,
                            col,
                            message: e,
                        })?
                }
                "on_proxy_fail" => {
                    cfg.on_proxy_fail =
                        OnProxyFail::from_str(&v).map_err(|e| ParseError::Parser {
                            line,
                            col,
                            message: e,
                        })?
                }
                other => {
                    return Err(ParseError::Parser {
                        line,
                        col,
                        message: format!("Unknown key '{}' in redsocks section", other),
                    });
                }
            }
        }
        Ok(())
    }

    fn populate_redudp(
        cfg: &mut RedudpConfig,
        entries: Vec<(String, String, usize, usize)>,
    ) -> Result<(), ParseError> {
        for (k, v, line, col) in entries {
            match k.as_str() {
                "local_ip" => cfg.local_ip = Self::parse_ip(&v, line, col)?,
                "local_port" => cfg.local_port = Self::parse_u16(&v, line, col)?,
                "ip" => cfg.ip = v,
                "port" => cfg.port = Self::parse_u16(&v, line, col)?,
                "login" => cfg.login = Some(v),
                "password" => cfg.password = Some(v),
                "dest_ip" => cfg.dest_ip = Some(Self::parse_ip(&v, line, col)?),
                "dest_port" => cfg.dest_port = Some(Self::parse_u16(&v, line, col)?),
                "udp_timeout" => cfg.udp_timeout = Self::parse_u64(&v, line, col)?,
                "udp_timeout_stream" => cfg.udp_timeout_stream = Self::parse_u64(&v, line, col)?,
                "max_pktqueue" => cfg.max_pktqueue = Self::parse_usize(&v, line, col)?,
                other => {
                    return Err(ParseError::Parser {
                        line,
                        col,
                        message: format!("Unknown key '{}' in redudp section", other),
                    });
                }
            }
        }
        Ok(())
    }

    fn populate_dnstc(
        cfg: &mut DnstcConfig,
        entries: Vec<(String, String, usize, usize)>,
    ) -> Result<(), ParseError> {
        for (k, v, line, col) in entries {
            match k.as_str() {
                "local_ip" => cfg.local_ip = Self::parse_ip(&v, line, col)?,
                "local_port" => cfg.local_port = Self::parse_u16(&v, line, col)?,
                other => {
                    return Err(ParseError::Parser {
                        line,
                        col,
                        message: format!("Unknown key '{}' in dnstc section", other),
                    });
                }
            }
        }
        Ok(())
    }

    fn populate_dnsu2t(
        cfg: &mut Dnsu2tConfig,
        entries: Vec<(String, String, usize, usize)>,
    ) -> Result<(), ParseError> {
        for (k, v, line, col) in entries {
            match k.as_str() {
                "local_ip" => cfg.local_ip = Self::parse_ip(&v, line, col)?,
                "local_port" => cfg.local_port = Self::parse_u16(&v, line, col)?,
                "remote_ip" => cfg.remote_ip = v,
                "remote_port" => cfg.remote_port = Self::parse_u16(&v, line, col)?,
                "inflight_max" => cfg.inflight_max = Self::parse_usize(&v, line, col)?,
                "remote_timeout" => cfg.remote_timeout = Self::parse_u64(&v, line, col)?,
                other => {
                    return Err(ParseError::Parser {
                        line,
                        col,
                        message: format!("Unknown key '{}' in dnsu2t section", other),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_example_config() {
        let conf = r#"
        base {
            log_debug = off;
            log_info = on;
            log = stderr;
            daemon = off;
            redirector = iptables;
            connpres_idle_timeout = 7440;
        }

        redsocks {
            local_ip = 127.0.0.1;
            local_port = 12345;
            listenq = 128;
            splice = false;
            ip = "example.org";
            port = 1080;
            type = socks5;
            login = "foobar";
            password = "baz";
            disclose_src = false;
            on_proxy_fail = close;
        }

        redudp {
            local_ip = 127.0.0.1;
            local_port = 10053;
            ip = 10.0.0.1;
            port = 1080;
            login = username;
            password = pazzw0rd;
            dest_ip = 8.8.8.8;
            dest_port = 53;
            udp_timeout = 30;
            udp_timeout_stream = 180;
        }

        dnstc {
            local_ip = 127.0.0.1;
            local_port = 5300;
        }

        dnsu2t {
            local_ip = 127.0.0.1;
            local_port = 5313;
            remote_ip = 8.8.8.8;
            remote_port = 53;
            inflight_max = 16;
            remote_timeout = 30;
        }
        "#;

        let parsed = ConfigParser::parse_str(conf).expect("parse failed");
        assert!(!parsed.base.log_debug);
        assert!(parsed.base.log_info);
        assert_eq!(parsed.base.log, "stderr");
        assert_eq!(parsed.base.redirector, "iptables");

        assert_eq!(parsed.redsocks.len(), 1);
        let r = &parsed.redsocks[0];
        assert_eq!(r.local_port, 12345);
        assert_eq!(r.ip, "example.org");
        assert_eq!(r.port, 1080);
        assert_eq!(r.proxy_type, ProxyType::Socks5);
        assert_eq!(r.login.as_deref(), Some("foobar"));
        assert_eq!(r.password.as_deref(), Some("baz"));

        assert_eq!(parsed.redudp.len(), 1);
        let u = &parsed.redudp[0];
        assert_eq!(u.local_port, 10053);
        assert_eq!(u.login.as_deref(), Some("username"));
        assert_eq!(u.dest_port, Some(53));

        assert_eq!(parsed.dnstc.len(), 1);
        assert_eq!(parsed.dnstc[0].local_port, 5300);

        assert_eq!(parsed.dnsu2t.len(), 1);
        assert_eq!(parsed.dnsu2t[0].local_port, 5313);
        assert_eq!(parsed.dnsu2t[0].inflight_max, 16);
    }
}
