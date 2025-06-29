use std::collections::HashMap;
use std::collections::VecDeque;
use crate::dis::Ins;

#[derive(Clone, Copy)]
enum Binop {
    Add,
    Sub,
    Mul,
    Mod,
    Eq,
}

#[derive(Clone)]
enum SymVal {
    Binop(Binop, Box<SymVal>, Box<SymVal>),
    Const(u64),
    FlagByte(u64),
    MemByte(u64),
}

impl SymVal {
    fn mk_add(a: Self, b: Self) -> Self {
        match (&a, &b) {
            (Self::Const(a), Self::Const(b)) => Self::Const(a + b),
            _ => Self::Binop(Binop::Add, Box::new(b), Box::new(a)),
        }
    }
    fn mk_mul(a: Self, b: Self) -> Self {
        match (&a, &b) {
            (Self::Const(a), Self::Const(b)) => Self::Const(a * b),
            _ => Self::Binop(Binop::Mul, Box::new(b), Box::new(a)),
        }
    }
}

impl std::fmt::Debug for SymVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Binop(op, l, r) => {
                write!(f, "({l:?} ")?;
                match op {
                    Binop::Add => write!(f, "+")?,
                    Binop::Sub => write!(f, "-")?,
                    Binop::Mul => write!(f, "*")?,
                    Binop::Mod => write!(f, "%")?,
                    Binop::Eq => write!(f, "==")?,
                }
                write!(f, " {r:?})")
            }
            Self::Const(v) => write!(f, "{v}"),
            Self::FlagByte(idx) => write!(f, "flag[{idx}]"),
            Self::MemByte(idx) => write!(f, "mem[{idx}]"),
        }
    }
}

#[derive(Clone)]
struct DecHead {
    pos: usize,
    stack: Vec<SymVal>,
}

struct Dec<'a> {
    ins: &'a HashMap<usize, Ins>,
    heads: VecDeque<DecHead>,
    output: Vec<(usize, String)>,
}

impl<'a> Dec<'a> {
    fn run(&mut self) {
        while let Some(head) = self.heads.pop_front() {
            self.run_at(head);
        }
    }

    fn run_at(&mut self, mut head: DecHead) -> Option<()> {
        let op = self.ins.get(&head.pos)?;
        let mut then = vec![head.pos + op.size()];
        let mut dec = None;
        match op {
            Ins::PushImm(v) => { head.stack.push(SymVal::Const(*v as u64)); }
            Ins::Pop => { head.stack.pop()?; }
            Ins::PushMem(v) => {
                if 640 <= *v && *v < 689 {
                    head.stack.push(SymVal::FlagByte(*v - 640));
                } else {
                    head.stack.push(SymVal::MemByte(*v));
                }
            }
            Ins::PopMem(v) => {
                let a = head.stack.pop()?;
                dec = Some(format!("memory[#{v:05x}] := {a:?}"));
            }
            Ins::Add => {
                let a = head.stack.pop()?;
                let b = head.stack.pop()?;
                head.stack.push(SymVal::mk_add(a, b));
            }
            Ins::Sub => {
                let a = head.stack.pop()?;
                let b = head.stack.pop()?;
                head.stack.push(SymVal::Binop(Binop::Sub, Box::new(b), Box::new(a)));
            }
            Ins::Mul => {
                let a = head.stack.pop()?;
                let b = head.stack.pop()?;
                head.stack.push(SymVal::mk_mul(a, b));
            }
            Ins::Mod => {
                let a = head.stack.pop()?;
                let b = head.stack.pop()?;
                head.stack.push(SymVal::Binop(Binop::Mod, Box::new(b), Box::new(a)));
            }
            Ins::Eq => {
                let a = head.stack.pop()?;
                let b = head.stack.pop()?;
                head.stack.push(SymVal::Binop(Binop::Eq, Box::new(b), Box::new(a)));
            }
            Ins::Goto(v) => {
                then = vec![*v as usize];
                dec = Some(format!("goto #{v:05x}"));
            }
            Ins::Jt(v) => {
                then.push(*v as usize);
                let a = head.stack.pop()?;
                dec = Some(format!("if ({a:?} == 1) goto #{v:05x}"));
            }
            Ins::Jnt(v) => {
                then.push(*v as usize);
                let a = head.stack.pop()?;
                dec = Some(format!("if ({a:?} != 1) goto #{v:05x}"));
            }
            Ins::Print => {
                let a = head.stack.pop()?;
                dec = Some(format!("print(chr({a:?}))"));
            }
            Ins::Exec => { 
                let a = head.stack.pop()?;
                dec = Some(format!("exec_decrypt({a:?})"));
            }
            Ins::Swap => {
                head.stack.pop()?;
                head.stack.pop()?;
                then.clear();
                dec = Some(format!("(swap)"));
            }
            Ins::Halt => { then.clear(); }
        }
        if let Some(dec) = dec {
            println!("{:05x}  {dec}", head.pos);
            self.output.push((head.pos + op.size(), dec));
        }
        if then.len() > 1 {
            for pos in &then[1..] {
                let mut nhead = head.clone();
                nhead.pos = *pos;
                self.heads.push_back(nhead);
            }
        }
        if !then.is_empty() {
            head.pos = then[0];
            self.heads.push_front(head);
        }
        Some(())
    }
}

pub fn dec(ins: &[(usize, Ins)]) -> Vec<(usize, String)> {
    let ins = ins.iter().copied().collect::<HashMap<_, _>>();
    let mut ctx = Dec {
        ins: &ins,
        heads: vec![DecHead {
            pos: 0,
            stack: Vec::new(),
        }].into(),
        output: Vec::new(),
    };
    ctx.run();
    ctx.output
}
