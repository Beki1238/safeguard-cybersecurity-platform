const cases = [
  {
    id: "SG-001",
    title: "Midnight Login",
    category: "LOG ANALYSIS",
    difficulty: "BEGINNER",
    description: "An account has accessed an internal archive outside its normal working hours.",
    evidence: [
      ["Account", "analyst01"],
      ["Source IP", "203.0.113.42 (fictional test address)"],
      ["Event time", "02:14 UTC"],
      ["Normal login window", "08:00–18:00 UTC"],
      ["Authentication", "Successful"]
    ],
    question: "What is the most reasonable next step?",
    answers: [
      "Immediately conclude the account has been hacked.",
      "Review surrounding logs and confirm whether the login was authorized.",
      "Delete the account and all its files.",
      "Ignore the event because authentication succeeded."
    ],
    correct: 1,
    explanation: "An unusual login time deserves investigation, but it does not prove an account compromise. Review related events and verify the activity with the account owner or authorized team.",
    lesson: "An alert is a lead to investigate, not proof of an attack."
  },
  {
    id: "SG-002",
    title: "Suspicious Link",
    category: "PHISHING ANALYSIS",
    difficulty: "BEGINNER",
    description: "An employee reports an urgent email claiming their account will be suspended.",
    evidence: [
      ["Sender", "security@example.invalid"],
      ["Subject", "URGENT: Account suspension"],
      ["Link", "https://login-example.invalid/verify"],
      ["Request", "Enter your password to prevent suspension"],
      ["Pressure tactic", "Immediate action demanded"]
    ],
    question: "Which detail is the strongest warning sign?",
    answers: [
      "The message contains a subject line.",
      "The message pressures the recipient to enter credentials through an unverified link.",
      "The message was delivered electronically.",
      "The message mentions an account."
    ],
    correct: 1,
    explanation: "Urgency combined with a request for credentials through an unverified link is a major phishing warning sign. Verify account issues through an independently trusted channel instead.",
    lesson: "Check the destination and verify the sender before trusting a request."
  },
  {
    id: "SG-003",
    title: "File Integrity Alert",
    category: "FILE ANALYSIS",
    difficulty: "INTERMEDIATE",
    description: "A routine integrity check reports that a document no longer matches its trusted reference hash.",
    evidence: [
      ["File", "quarterly_report.txt"],
      ["Trusted reference hash", "aaaaaaaaaaaaaaaa"],
      ["Current file hash", "bbbbbbbbbbbbbbbb"],
      ["Integrity result", "MISMATCH"],
      ["Malware scan", "No result available"]
    ],
    question: "What can you conclude from this evidence alone?",
    answers: [
      "The file is definitely malware.",
      "An attacker definitely modified the file.",
      "The current file content differs from the content represented by the trusted reference hash.",
      "The computer is definitely compromised."
    ],
    correct: 2,
    explanation: "A hash mismatch indicates that the file content differs from the trusted reference, assuming the reference is valid and the same hashing method was used. It does not, by itself, establish why the file changed.",
    lesson: "Integrity checks reveal differences; additional evidence is needed to explain them."
  }
];

const STORAGE_KEY = "safeguard-investigations-progress-v1";

let currentCaseId = null;
let selectedAnswers = {};
let feedbackVisible = {};
let progress = loadProgress();

function loadProgress() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
    if (
      saved &&
      Array.isArray(saved.solved) &&
      Number.isFinite(saved.xp)
    ) {
      return {
        solved: saved.solved.filter(id =>
          cases.some(item => item.id === id)
        ),
        xp: Math.max(0, saved.xp)
      };
    }
  } catch (error) {
    console.warn("Progress could not be loaded.", error);
  }

  return { solved: [], xp: 0 };
  function saveProgress() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(progress));
  } catch (error) {
    console.warn("Progress could not be saved in this browser.", error);
  }
}

function renderStats() {
  document.getElementById("case-count").textContent =
    String(cases.length).padStart(2, "0");

  document.getElementById("solved-count").textContent =
    String(progress.solved.length).padStart(2, "0");

  document.getElementById("xp-count").textContent =
    String(progress.xp).padStart(3, "0");
}

function renderCaseList() {
  const list = document.getElementById("case-list");
  list.replaceChildren();

  cases.forEach(item => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "case-button";

    if (item.id === currentCaseId) {
      button.classList.add("active");
    }

    if (progress.solved.includes(item.id)) {
      button.classList.add("completed");
    }

    const meta = document.createElement("span");
    meta.className = "case-meta";
    meta.textContent = item.id + " / " + item.category;

    const title = document.createElement("strong");
    title.textContent = item.title;

    const difficulty = document.createElement("small");
    difficulty.textContent = item.difficulty;

    button.append(meta, title, difficulty);
    button.addEventListener("click", () => selectCase(item.id));
    list.appendChild(button);
  });
}

function selectCase(id) {
  currentCaseId = id;
  renderCaseList();
  renderCase();
}

function makeEvidence(item) {
  const container = document.createElement("div");
  container.className = "evidence";

  item.evidence.forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "evidence-item";

    const heading = document.createElement("strong");
    heading.textContent = label;

    const detail = document.createElement("span");
    detail.textContent = value;

    row.append(heading, detail);
    container.appendChild(row);
  });

  return container;
}

function renderCase() {
  const container = document.getElementById("case-content");
  container.replaceChildren();

  const item = cases.find(entry => entry.id === currentCaseId);

  if (!item) {
    const message = document.createElement("p");
    message.textContent = "Select an investigation from the directory.";
    container.appendChild(message);
    return;
  }

  const header = document.createElement("div");
  header.className = "case-header";

  const id = document.createElement("span");
  id.className = "case-id";
  id.textContent = "CASE FILE / " + item.id;

  const title = document.createElement("h2");
  title.textContent = item.title;

  const description = document.createElement("p");
  description.textContent = item.description;

  const difficulty = document.createElement("span");
  difficulty.className = "difficulty";
  difficulty.textContent = item.difficulty;

  header.append(id, title, description, difficulty);
  container.appendChild(header);

  const evidenceLabel = document.createElement("h3");
  evidenceLabel.className = "section-label";
  evidenceLabel.textContent = "01 / AVAILABLE EVIDENCE";
  container.append(evidenceLabel, makeEvidence(item));

  const questionLabel = document.createElement("h3");
  questionLabel.className = "section-label";
  questionLabel.textContent = "02 / ANALYST DECISION";
  container.appendChild(questionLabel);

  const question = document.createElement("p");
  question.className = "question";
  question.textContent = item.question;
  container.appendChild(question);

  const form = document.createElement("form");
  const answers = document.createElement("div");
  answers.className = "answers";

  item.answers.forEach((answer, index) => {
    const label = document.createElement("label");
    label.className = "answer-option";

    const input = document.createElement("input");
    input.type = "radio";
    input.name = "investigation-answer";
    input.value = String(index);
    input.checked = selectedAnswers[item.id] === index;
    const text = document.createElement("span");
    text.textContent = answer;

    input.addEventListener("change", () => {
      selectedAnswers[item.id] = index;
    });

    label.append(input, text);
    answers.appendChild(label);
  });

  const submit = document.createElement("button");
  submit.type = "submit";
  submit.className = "primary-button";
  submit.textContent = progress.solved.includes(item.id)
    ? "Review answer"
    : "Submit assessment";

  form.append(answers, submit);

  form.addEventListener("submit", event => {
    event.preventDefault();

    if (!Number.isInteger(selectedAnswers[item.id])) {
      showFeedback(item, null);
      return;
    }

    const answer = selectedAnswers[item.id];

    if (answer === item.correct && !progress.solved.includes(item.id)) {
      progress.solved.push(item.id);
      progress.xp += 100;
      saveProgress();
      renderStats();
      renderCaseList();
    }

    showFeedback(item, answer);
  });

  container.appendChild(form);

  if (feedbackVisible[item.id]) {
    showFeedback(item, selectedAnswers[item.id]);
  }
}

function showFeedback(item, answer) {
  const container = document.getElementById("case-content");
  const oldFeedback = container.querySelector(".feedback");

  if (oldFeedback) {
    oldFeedback.remove();
  }

  const feedback = document.createElement("section");
  feedback.className = "feedback";

  const heading = document.createElement("h3");
  const message = document.createElement("p");
  const lesson = document.createElement("p");

  lesson.style.marginTop = "10px";

  if (answer === null) {
    feedback.classList.add("incorrect");
    heading.textContent = "Decision required";
    message.textContent = "Select an answer before submitting your assessment.";
    lesson.textContent = "Review the available evidence before making your decision.";
  } else if (answer === item.correct) {
    feedback.classList.add("correct");
    heading.textContent = "✓ Assessment correct";

    message.textContent = progress.solved.includes(item.id)
      ? "Good analysis. " + item.explanation
      : item.explanation;

    lesson.textContent = "KEY TAKEAWAY: " + item.lesson;
    feedbackVisible[item.id] = true;
  } else {
    feedback.classList.add("incorrect");
    heading.textContent = "Not quite — review the evidence";
    message.textContent = item.explanation;
    lesson.textContent = "KEY TAKEAWAY: " + item.lesson;
    feedbackVisible[item.id] = true;
  }

  feedback.append(heading, message, lesson);
  container.appendChild(feedback);
}

renderStats();
renderCaseList();

if (cases.length > 0) {
  selectCase(cases[0].id);
}
}
