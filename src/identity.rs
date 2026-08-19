use anyhow::{Context, Result};

const MODIFIERS: &[&str] = &[
    "安静",
    "熬夜",
    "迷路",
    "发呆",
    "漂浮",
    "隐身",
    "慢热",
    "走神",
    "清醒",
    "困倦",
    "开心",
    "谨慎",
    "勇敢",
    "温柔",
    "固执",
    "好奇",
    "神秘",
    "自由",
    "孤独",
    "慵懒",
    "闪光",
    "透明",
    "褪色",
    "断线",
    "离线",
    "满电",
    "低调",
    "失眠",
    "贪吃",
    "爱笑",
    "怕冷",
    "追风",
    "看云",
    "听雨",
    "数星星",
    "喝咖啡",
    "晒太阳",
    "等日落",
    "穿雨衣",
    "戴耳机",
    "藏秘密",
    "写代码",
    "捡贝壳",
    "种蘑菇",
    "收集月光",
    "寻找信号",
    "忘记密码",
    "拒绝加班",
    "偶尔上线",
    "正在缓冲",
    "保持沉默",
    "路过这里",
    "来自未来",
    "没有名字",
    "不会游泳",
    "不吃香菜",
    "想要放假",
    "偷偷摸鱼",
    "认真潜水",
    "原地待机",
    "逆风飞行",
    "缓慢加载",
    "保持匿名",
    "等待回复",
];

const SUBJECTS: &[&str] = &[
    "海獭",
    "企鹅",
    "水母",
    "鲸鱼",
    "海豹",
    "河豚",
    "章鱼",
    "海星",
    "信天翁",
    "猫头鹰",
    "狐狸",
    "浣熊",
    "松鼠",
    "刺猬",
    "兔子",
    "黑猫",
    "柴犬",
    "羊驼",
    "树懒",
    "熊猫",
    "壁虎",
    "蜗牛",
    "萤火虫",
    "蝴蝶",
    "飞蛾",
    "乌鸦",
    "麻雀",
    "白鹭",
    "鹦鹉",
    "仙人掌",
    "蘑菇",
    "蒲公英",
    "小行星",
    "月亮",
    "云朵",
    "雨滴",
    "雪花",
    "影子",
    "回声",
    "像素",
    "光标",
    "终端",
    "路由器",
    "收音机",
    "旧电视",
    "机器人",
    "宇航员",
    "潜水员",
    "邮差",
    "守夜人",
    "观察员",
    "旅行者",
    "陌生人",
    "魔术师",
    "炼金术士",
    "程序员",
    "信号塔",
    "黑胶唱片",
    "纸飞机",
    "自动售货机",
    "故障灯",
    "空文件夹",
    "匿名用户",
    "局域网幽灵",
];

/// Generates a display-safe anonymous nickname in the form “xxx的xxx”.
pub fn random_nickname() -> Result<String> {
    let mut entropy = [0_u8; 4];
    getrandom::fill(&mut entropy).context("failed to generate a random nickname")?;
    Ok(nickname_from_entropy(entropy))
}

fn nickname_from_entropy(entropy: [u8; 4]) -> String {
    let modifier = usize::from(u16::from_le_bytes([entropy[0], entropy[1]]));
    let subject = usize::from(u16::from_le_bytes([entropy[2], entropy[3]]));
    format!(
        "{}的{}",
        MODIFIERS[modifier % MODIFIERS.len()],
        SUBJECTS[subject % SUBJECTS.len()]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::sanitize_nickname;

    #[test]
    fn generated_names_have_the_expected_chinese_shape() {
        for entropy in [[0, 0, 0, 0], [255, 255, 255, 255], [19, 73, 41, 92]] {
            let nickname = nickname_from_entropy(entropy);
            let (modifier, subject) = nickname.split_once('的').unwrap();
            assert!(!modifier.is_empty());
            assert!(!subject.is_empty());
            assert_eq!(sanitize_nickname(&nickname).unwrap(), nickname);
        }
    }

    #[test]
    fn the_word_lists_offer_many_combinations() {
        assert!(MODIFIERS.len() >= 64);
        assert!(SUBJECTS.len() >= 64);
        assert!(MODIFIERS.len() * SUBJECTS.len() >= 4_096);
    }
}
