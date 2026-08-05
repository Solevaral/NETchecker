//! Базовые типы диагностики: слои OSI, статусы, результаты проверок,
//! узлы схемы сети и итоговый вердикт.

/// Уровень модели OSI, к которому относится проверка.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    L1Physical,
    L2Link,
    L3Network,
    L4Transport,
    L5Session,
    L6Presentation,
    L7Application,
}

impl Layer {
    pub const ALL: [Layer; 7] = [
        Layer::L1Physical,
        Layer::L2Link,
        Layer::L3Network,
        Layer::L4Transport,
        Layer::L5Session,
        Layer::L6Presentation,
        Layer::L7Application,
    ];

    /// Короткая метка вроде «L3».
    pub fn code(self) -> &'static str {
        match self {
            Layer::L1Physical => "L1",
            Layer::L2Link => "L2",
            Layer::L3Network => "L3",
            Layer::L4Transport => "L4",
            Layer::L5Session => "L5",
            Layer::L6Presentation => "L6",
            Layer::L7Application => "L7",
        }
    }

    /// Название уровня для сетевика.
    pub fn title(self) -> &'static str {
        match self {
            Layer::L1Physical => "Физический",
            Layer::L2Link => "Канальный",
            Layer::L3Network => "Сетевой",
            Layer::L4Transport => "Транспортный",
            Layer::L5Session => "Сеансовый",
            Layer::L6Presentation => "Представления",
            Layer::L7Application => "Прикладной",
        }
    }

    /// То же самое человеческим языком.
    pub fn plain(self) -> &'static str {
        match self {
            Layer::L1Physical => "кабель, Wi-Fi, сама «железка»",
            Layer::L2Link => "связь с роутером в вашей квартире",
            Layer::L3Network => "адреса и маршрут до интернета",
            Layer::L4Transport => "соединения с серверами по портам",
            Layer::L5Session => "установка и удержание сессии",
            Layer::L6Presentation => "шифрование и сертификаты",
            Layer::L7Application => "сайты, DNS-имена, приложения",
        }
    }
}

/// Состояние отдельной проверки или узла схемы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Ещё не запускалась.
    Pending,
    /// Выполняется прямо сейчас.
    Running,
    /// Всё в порядке.
    Ok,
    /// Работает, но с проблемами.
    Warn,
    /// Не работает.
    Fail,
    /// Пропущена — с объяснением почему.
    Skipped,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pending => "ожидает",
            Status::Running => "идёт проверка",
            Status::Ok => "в порядке",
            Status::Warn => "есть замечания",
            Status::Fail => "не работает",
            Status::Skipped => "пропущено",
        }
    }

    /// Знак для строки отчёта — чтобы цвет не был единственным носителем смысла.
    pub fn glyph(self) -> &'static str {
        match self {
            Status::Pending => "·",
            Status::Running => "…",
            Status::Ok => "OK",
            Status::Warn => "!",
            Status::Fail => "X",
            Status::Skipped => "–",
        }
    }

    /// Худший из двух статусов — для сворачивания списка проверок в статус узла.
    pub fn worse(self, other: Status) -> Status {
        fn rank(s: Status) -> u8 {
            match s {
                Status::Pending => 0,
                Status::Skipped => 1,
                Status::Running => 2,
                Status::Ok => 3,
                Status::Warn => 4,
                Status::Fail => 5,
            }
        }
        if rank(other) > rank(self) {
            other
        } else {
            self
        }
    }
}

/// Узел схемы сети — от вашего компьютера до целевого сайта.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeId {
    /// Ваш компьютер.
    Pc,
    /// Домашний роутер / точка доступа.
    Router,
    /// Сеть провайдера.
    Provider,
    /// Средства фильтрации трафика (ТСПУ/DPI).
    Dpi,
    /// Интернет как таковой, включая DNS.
    Internet,
    /// Проверяемый сайт.
    Target,
}

impl NodeId {
    /// Порядок узлов слева направо на схеме.
    pub const CHAIN: [NodeId; 6] = [
        NodeId::Pc,
        NodeId::Router,
        NodeId::Provider,
        NodeId::Dpi,
        NodeId::Internet,
        NodeId::Target,
    ];

    pub fn title(self) -> &'static str {
        match self {
            NodeId::Pc => "Ваш компьютер",
            NodeId::Router => "Роутер",
            NodeId::Provider => "Провайдер",
            NodeId::Dpi => "Фильтрация",
            NodeId::Internet => "Интернет",
            NodeId::Target => "Сайт",
        }
    }
}

/// Состояние узла схемы: статус, подпись и адрес.
#[derive(Debug, Clone)]
pub struct NodeState {
    pub id: NodeId,
    pub status: Status,
    /// Уточнение под названием узла — например имя интерфейса или AS провайдера.
    pub subtitle: String,
    /// IP-адрес узла, если он известен.
    pub address: Option<String>,
}

impl NodeState {
    pub fn new(id: NodeId) -> Self {
        Self {
            id,
            status: Status::Pending,
            subtitle: String::new(),
            address: None,
        }
    }
}

/// Результат одной проверки. Описание всегда в двух видах: для человека и для сетевика.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Стабильный идентификатор, по нему UI обновляет уже показанную строку.
    pub id: &'static str,
    pub layer: Layer,
    pub node: NodeId,
    pub status: Status,
    /// Заголовок строки в отчёте.
    pub title: String,
    /// Объяснение для человека без знаний сети.
    pub simple: String,
    /// Объяснение для того, кто разбирается.
    pub expert: String,
    /// Сырые данные: адреса, коды ошибок, тайминги.
    pub evidence: Vec<String>,
}

impl CheckResult {
    pub fn new(id: &'static str, layer: Layer, node: NodeId, title: impl Into<String>) -> Self {
        Self {
            id,
            layer,
            node,
            status: Status::Running,
            title: title.into(),
            simple: String::new(),
            expert: String::new(),
            evidence: Vec::new(),
        }
    }

    pub fn finish(
        mut self,
        status: Status,
        simple: impl Into<String>,
        expert: impl Into<String>,
    ) -> Self {
        self.status = status;
        self.simple = simple.into();
        self.expert = expert.into();
        self
    }

    pub fn with_evidence(mut self, line: impl Into<String>) -> Self {
        self.evidence.push(line.into());
        self
    }
}

/// Итоговый вывод: что именно сломалось, где и что с этим делать.
#[derive(Debug, Clone)]
pub struct Diagnosis {
    /// Одна фраза крупным шрифтом.
    pub headline: String,
    pub simple: String,
    pub expert: String,
    /// Конкретные шаги пользователю.
    pub actions: Vec<String>,
    /// Ребро схемы, на котором обрыв: трафик доходит до `.0`, но не проходит к `.1`.
    pub break_edge: Option<(NodeId, NodeId)>,
    pub status: Status,
}

impl Diagnosis {
    pub fn unknown() -> Self {
        Self {
            headline: "Диагностика ещё не запускалась".to_string(),
            simple: "Нажмите «Проверить», чтобы выяснить состояние подключения.".to_string(),
            expert: String::new(),
            actions: Vec::new(),
            break_edge: None,
            status: Status::Pending,
        }
    }
}

/// Полная картина: схема сети, все проверки и вердикт.
#[derive(Debug, Clone)]
pub struct Report {
    pub nodes: Vec<NodeState>,
    pub checks: Vec<CheckResult>,
    pub diagnosis: Diagnosis,
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}

impl Report {
    pub fn new() -> Self {
        Self {
            nodes: NodeId::CHAIN.iter().map(|&id| NodeState::new(id)).collect(),
            checks: Vec::new(),
            diagnosis: Diagnosis::unknown(),
        }
    }

    pub fn node_mut(&mut self, id: NodeId) -> &mut NodeState {
        self.nodes
            .iter_mut()
            .find(|n| n.id == id)
            .expect("узел всегда есть в цепочке")
    }

    /// Добавляет результат или заменяет уже имеющийся с тем же `id`,
    /// заодно подтягивая статус соответствующего узла схемы.
    pub fn apply(&mut self, result: CheckResult) {
        let node = result.node;
        match self.checks.iter_mut().find(|c| c.id == result.id) {
            Some(slot) => *slot = result,
            None => self.checks.push(result),
        }
        let rolled = self
            .checks
            .iter()
            .filter(|c| c.node == node)
            .fold(Status::Pending, |acc, c| acc.worse(c.status));
        self.node_mut(node).status = rolled;
    }

    pub fn checks_of(&self, layer: Layer) -> impl Iterator<Item = &CheckResult> {
        self.checks.iter().filter(move |c| c.layer == layer)
    }
}
