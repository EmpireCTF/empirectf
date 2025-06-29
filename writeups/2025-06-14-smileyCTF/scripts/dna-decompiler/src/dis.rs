use std::ops::Range;

#[derive(Clone, Copy, Debug)]
pub enum Ins {
    PushImm(u64),
    Pop,
    PushMem(u64),
    PopMem(u64),
    Add,
    Sub,
    Mul,
    Mod,
    Eq,
    Goto(u64),
    Jt(u64),
    Jnt(u64),
    Print,
    Exec,
    Swap,
    Halt,
}

impl Ins {
    pub fn size(&self) -> usize {
        match self {
            Self::PushImm(_)
            | Self::PushMem(_)
            | Self::PopMem(_)
            | Self::Goto(_)
            | Self::Jt(_)
            | Self::Jnt(_) => 12,
            _ => 2,
        }
    }
}

struct Dis<'a> {
    data: &'a [u8],
    pos: usize,
    coding: [u8; 4],
    output: Vec<(usize, Ins)>,
}

impl<'a> Dis<'a> {
    fn decode(&self, range: Range<usize>) -> u64 {
        range
            .enumerate()
            .map(|(i, ci)| (self.coding[match self.data[ci] {
                b'A' => 0,
                b'T' => 1,
                b'G' => 2,
                b'C' => 3,
                _ => unreachable!(),
            }] as u64) << 2 * i)
            .sum()
    }

    fn run(&mut self) {
        while self.pos < self.data.len() {
            let start_pos = self.pos;
            self.pos += 2;
            let op = self.decode(start_pos..start_pos + 2);
            let imm = if matches!(op, 0 | 2 | 3 | 9 | 10 | 11) {
                self.pos += 10;
                self.decode(start_pos + 2..start_pos + 12)
            } else {
                0
            };
            let (stop, ins) = match op {
                0 => (false, Ins::PushImm(imm)),
                1 => (false, Ins::Pop),
                2 => (false, Ins::PushMem(imm)),
                3 => (false, Ins::PopMem(imm)),
                4 => (false, Ins::Add),
                5 => (false, Ins::Sub),
                6 => (false, Ins::Mul),
                7 => (false, Ins::Mod),
                8 => (false, Ins::Eq),
                9 => (false, Ins::Goto(imm)),
                10 => (false, Ins::Jt(imm)),
                11 => (false, Ins::Jnt(imm)),
                12 => (false, Ins::Print),
                13 => (true, Ins::Exec),
                14 => (true, Ins::Swap),
                15 => (false, Ins::Halt),
                _ => unreachable!(),
            };
            self.output.push((start_pos, ins));
            if stop {
                break;
            }
        }
    }
}

pub fn dis(
    data: &[u8],
    pos: usize,
    coding: [u8; 4],
) -> Vec<(usize, Ins)> {
    let mut ctx = Dis {
        data,
        pos,
        coding,
        output: Vec::new(),
    };
    ctx.run();
    ctx.output
}
