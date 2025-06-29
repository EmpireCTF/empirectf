use std::collections::HashMap;
use crate::dis::Ins;

pub struct Show<'a> {
    data: &'a [u8],
    lines: HashMap<usize, (
        Option<String>,
        Option<String>,
        Option<String>,
    )>,
}

impl<'a> Show<'a> {
    pub fn add_dis(&mut self, pos: usize, coding: [u8; 4], ins: &[(usize, Ins)]) {
        self.lines.entry(pos)
            .or_default()
            .0 = Some(format!("section at {pos:05x}, coding: {coding:?}"));
        for (pos, ins) in ins {
            let show_ins = match ins {
                Ins::PushImm(v) => format!("push(#{v:08x})"),
                Ins::Pop => "pop()".to_string(),
                Ins::PushMem(v) => format!("push(mem[#{v:04x}])"),
                Ins::PopMem(v) => format!("mem[#{v:04x}] := pop()"),
                Ins::Add => "push(pop() + pop())".to_string(),
                Ins::Sub => "push(pop() - pop())".to_string(),
                Ins::Mul => "push(pop() * pop())".to_string(),
                Ins::Mod => "push(pop() % pop())".to_string(),
                Ins::Eq => "push(pop() == pop())".to_string(),
                Ins::Goto(v) => format!("goto(#{v:05x})"),
                Ins::Jt(v) => format!("if (pop() == 1) goto(#{v:05x})"),
                Ins::Jnt(v) => format!("if (pop() != 1) goto(#{v:05x})"),
                Ins::Print => "print(pop())".to_string(),
                Ins::Exec => "exec(pop())".to_string(),
                Ins::Swap => "swap(pop(), pop())".to_string(),
                Ins::Halt => "halt()".to_string(),
            };
            self.lines.entry(*pos + ins.size())
                .or_default()
                .1 = Some(show_ins);
        }
    }

    pub fn add_dec(&mut self, dec: &[(usize, String)]) {
        for (pos, dec) in dec {
            self.lines.entry(*pos)
                .or_default()
                .2 = Some(dec.to_string());
        }
    }

    pub fn show(&self) -> String {
        let mut out = String::new();
        let mut line = String::new();
        let mut line_cur = 0;
        for pos in 0..self.data.len() {
            if let Some((Some(section), _, _)) = self.lines.get(&pos) {
                if line_cur != 0 {
                    line.push('\n');
                    out.push_str(&line);
                    line = String::new();
                }
                line.push_str("      ; ");
                line.push_str(section);
                line.push('\n');
                out.push_str(&line);
                line_cur = 0;
                line = String::new();
            }
            if line_cur == 0 {
                line.push_str(&format!("{pos:05x} : "));
            }
            line.push(char::from_u32(self.data[pos] as u32).unwrap());
            let mut force_break = false;
            if let Some((_, Some(dis), _)) = self.lines.get(&(pos + 1)) {
                line.push_str(&" ".repeat(24 - line_cur - 8));
                line.push_str(dis);
                force_break = true;
            }
            if let Some((_, _, Some(dec))) = self.lines.get(&(pos + 1)) {
                line.push_str(&" ".repeat(55 - line.len()));
                line.push_str(dec);
                force_break = true;
            }
            if force_break {
                line.push('\n');
                out.push_str(&line);
                line_cur = 0;
                line = String::new();
            } else {
                line_cur += 1;
                if line_cur >= 16 {
                    line.push('\n');
                    out.push_str(&line);
                    line_cur = 0;
                    line = String::new();
                }
            }
        }
        out
    }
}

pub fn init<'a>(data: &'a [u8]) -> Show<'a> {
    Show {
        data,
        lines: HashMap::new(),
    }
}
