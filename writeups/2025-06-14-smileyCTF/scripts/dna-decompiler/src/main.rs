mod dec;
mod dis;
mod show;

const SECTIONS: &[(usize, [u8; 4])] = &[
    (0x0000, [0, 1, 2, 3]),
    (0x3B70, [1, 2, 3, 0]),
    (0x76E0, [3, 0, 2, 1]),
    (0xB250, [2, 0, 1, 3]),
    (0xEDC0, [2, 0, 1, 3]),
];

fn main() {
    let code_dna = std::fs::read("vm.dna").unwrap();

    let section_ins = SECTIONS.iter()
        .map(|(pos, coding)| dis::dis(&code_dna, *pos, *coding))
        .collect::<Vec<_>>();
    let ins_all = section_ins.clone().into_iter().flatten().collect::<Vec<_>>();

    let dec = dec::dec(&ins_all);

    let mut out = show::init(&code_dna);
    SECTIONS.iter()
        .zip(&section_ins)
        .for_each(|((pos, coding), ins)| out.add_dis(*pos, *coding, ins));
    out.add_dec(&dec);
    std::fs::write("decomp.txt", out.show()).unwrap();
}
