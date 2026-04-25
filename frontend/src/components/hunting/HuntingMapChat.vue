<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";

import api from "@/services/api";

type Comment = {
  id: string;
  author: string;
  content: string;
  type: "message" | "system";
  created_at: string | null;
};

const props = defineProps<{
  mapId: string;
  visible: boolean;
}>();

const emit = defineEmits<{
  close: [];
}>();

const comments = ref<Comment[]>([]);
const newMessage = ref("");
const sending = ref(false);
const minimized = ref(false);
const showHint = ref(true);
const scrollEl = ref<HTMLDivElement | null>(null);

const HELP_TEXT = `📋 Tag Workflow Guide
━━━━━━━━━━━━━━━━━━━
🟡 Investigating — Analyze / exploit node
⚪ Accepted Risk — No need to do more
🟢 Resolved — Patched

💡 How to tag?:
1. Click to node on hunting graph
2. Bottom sidebar, Choose tag from dropdown
3. Tag will be display on chat

💬 Type /help to see this message again`;

// Dragging state
const popupEl = ref<HTMLDivElement | null>(null);
const posX = ref<number | null>(null);
const posY = ref<number | null>(null);
let dragging = false;
let dragStartX = 0;
let dragStartY = 0;
let dragOffsetX = 0;
let dragOffsetY = 0;

// Polling
let pollTimer: ReturnType<typeof setInterval> | null = null;

async function fetchComments() {
  if (!props.mapId) return;
  try {
    const { data } = await api.get(`/hunting-maps/${encodeURIComponent(props.mapId)}/comments`);
    comments.value = data.items ?? [];
  } catch (error) {
    console.error(error);
  }
}

async function sendMessage() {
  const content = newMessage.value.trim();
  if (!content || sending.value) return;

  // Handle /help command locally
  if (content.toLowerCase() === "/help") {
    comments.value.push({
      id: `help-${Date.now()}`,
      author: "System",
      content: HELP_TEXT,
      type: "system",
      created_at: new Date().toISOString(),
    });
    newMessage.value = "";
    await nextTick();
    scrollToBottom();
    return;
  }

  sending.value = true;
  try {
    const { data } = await api.post(`/hunting-maps/${encodeURIComponent(props.mapId)}/comments`, { content });
    comments.value.push(data);
    newMessage.value = "";
    await nextTick();
    scrollToBottom();
  } catch (error) {
    console.error(error);
  } finally {
    sending.value = false;
  }
}

function scrollToBottom() {
  if (scrollEl.value) {
    scrollEl.value.scrollTop = scrollEl.value.scrollHeight;
  }
}

function formatTime(iso: string | null) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function formatDate(iso: string | null) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}`;
}

// Drag handlers
function onDragStart(e: MouseEvent) {
  if (!popupEl.value) return;
  dragging = true;
  dragStartX = e.clientX;
  dragStartY = e.clientY;
  const rect = popupEl.value.getBoundingClientRect();
  dragOffsetX = posX.value ?? rect.left;
  dragOffsetY = posY.value ?? rect.top;
  document.addEventListener("mousemove", onDragMove);
  document.addEventListener("mouseup", onDragEnd);
}

function onDragMove(e: MouseEvent) {
  if (!dragging) return;
  posX.value = dragOffsetX + (e.clientX - dragStartX);
  posY.value = dragOffsetY + (e.clientY - dragStartY);
}

function onDragEnd() {
  dragging = false;
  document.removeEventListener("mousemove", onDragMove);
  document.removeEventListener("mouseup", onDragEnd);
}

function startPolling() {
  stopPolling();
  pollTimer = setInterval(fetchComments, 15000);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

watch(() => props.visible, async (val) => {
  if (val) {
    await fetchComments();
    await nextTick();
    scrollToBottom();
    startPolling();
  } else {
    stopPolling();
  }
});

watch(() => props.mapId, () => {
  comments.value = [];
  if (props.visible) fetchComments();
});

onMounted(() => {
  if (props.visible) {
    fetchComments();
    startPolling();
  }
});

onBeforeUnmount(() => {
  stopPolling();
  document.removeEventListener("mousemove", onDragMove);
  document.removeEventListener("mouseup", onDragEnd);
});
</script>

<template>
  <Teleport to="body">
    <Transition name="chat-pop">
      <div
        v-if="visible"
        ref="popupEl"
        class="fixed z-[100] flex flex-col rounded-[1.2rem] border border-white/10 bg-slate-900/98 shadow-2xl shadow-black/50 backdrop-blur-xl"
        :class="minimized ? 'h-11' : 'h-[480px]'"
        :style="{
          width: '380px',
          left: posX !== null ? `${posX}px` : 'auto',
          top: posY !== null ? `${posY}px` : 'auto',
          right: posX === null ? '24px' : 'auto',
          bottom: posY === null ? '24px' : 'auto',
        }"
      >
        <!-- Header (draggable) -->
        <div
          class="flex shrink-0 cursor-move items-center justify-between rounded-t-[1.2rem] border-b border-white/10 bg-slate-800/60 px-4 py-2.5"
          @mousedown.prevent="onDragStart"
        >
          <div class="flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
            <span class="text-sm font-semibold text-white">Map Discussion</span>
            <span class="rounded-full bg-white/[0.06] px-2 py-0.5 text-[10px] text-slate-400">{{ comments.length }}</span>
          </div>
          <div class="flex items-center gap-1">
            <!-- Minimize -->
            <button
              type="button"
              class="flex h-6 w-6 items-center justify-center rounded-lg text-slate-400 transition hover:bg-white/[0.08] hover:text-white"
              :title="minimized ? 'Expand' : 'Minimize'"
              @click.stop="minimized = !minimized"
            >
              <svg xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path v-if="!minimized" stroke-linecap="round" d="M5 12h14" />
                <path v-else stroke-linecap="round" d="M4 8V5a1 1 0 0 1 1-1h3M4 16v3a1 1 0 0 0 1 1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3" />
              </svg>
            </button>
            <!-- Close -->
            <button
              type="button"
              class="flex h-6 w-6 items-center justify-center rounded-lg text-slate-400 transition hover:bg-red-500/20 hover:text-red-300"
              title="Close"
              @click.stop="emit('close')"
            >
              <svg xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        <!-- Message list -->
        <div
          v-if="!minimized"
          ref="scrollEl"
          class="flex-1 overflow-y-auto px-4 py-3 space-y-3"
        >
          <!-- Onboarding hint banner -->
          <div
            v-if="showHint"
            class="relative rounded-xl border border-orange-400/15 bg-orange-400/[0.05] px-3.5 py-2.5 text-[11px] leading-relaxed text-slate-300"
          >
            <button
              type="button"
              class="absolute right-2 top-2 text-slate-500 hover:text-white transition"
              @click="showHint = false"
              title="Dismiss"
            >&times;</button>
            <p class="font-semibold text-orange-300 mb-1">💡 Quick Guide</p>
            <p>Click node → chọn tag ở sidebar dropdown (<span class="text-amber-400">Investigating</span> · <span class="text-slate-400">Accepted Risk</span> · <span class="text-green-400">Resolved</span>)</p>
            <p class="mt-1 text-slate-500">Type <code class="rounded bg-white/[0.06] px-1 text-orange-300">/help</code> to view help</p>
          </div>

          <div v-if="comments.length === 0 && !showHint" class="flex h-full items-center justify-center">
            <p class="text-xs text-slate-500">No messages yet. Start the discussion!</p>
          </div>

          <template v-for="(c, i) in comments" :key="c.id">
            <!-- Date separator -->
            <div
              v-if="i === 0 || formatDate(c.created_at) !== formatDate(comments[i - 1].created_at)"
              class="flex items-center gap-2 py-1"
            >
              <span class="h-px flex-1 bg-white/[0.06]" />
              <span class="text-[10px] text-slate-500">{{ formatDate(c.created_at) }}</span>
              <span class="h-px flex-1 bg-white/[0.06]" />
            </div>

            <!-- System message -->
            <div v-if="c.type === 'system'" class="flex justify-center">
              <span
                v-if="c.id.startsWith('help-')"
                class="whitespace-pre-wrap rounded-xl border border-orange-400/15 bg-orange-400/[0.04] px-4 py-3 text-[11px] leading-relaxed text-slate-300"
              >{{ c.content }}</span>
              <span v-else class="rounded-full bg-white/[0.04] px-3 py-1 text-[11px] text-slate-400" v-html="c.content.replace(/\*\*(.*?)\*\*/g, '<b class=&quot;text-white&quot;>$1</b>').replace(/`(.*?)`/g, '<code class=&quot;rounded bg-orange-400/10 px-1 text-orange-300&quot;>$1</code>')" />
            </div>

            <!-- User message -->
            <div v-else class="group">
              <div class="flex items-baseline gap-2">
                <span class="text-xs font-semibold text-orange-300">{{ c.author }}</span>
                <span class="text-[10px] text-slate-500">{{ formatTime(c.created_at) }}</span>
              </div>
              <p class="mt-0.5 whitespace-pre-wrap text-sm leading-relaxed text-slate-200">{{ c.content }}</p>
            </div>
          </template>
        </div>

        <!-- Input bar -->
        <div
          v-if="!minimized"
          class="shrink-0 border-t border-white/10 px-3 py-2.5"
        >
          <div class="flex items-end gap-2">
            <textarea
              v-model="newMessage"
              rows="1"
              placeholder="Message or /help..."
              class="max-h-24 min-h-[2.25rem] flex-1 resize-none rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-orange-400/35"
              @keydown.enter.exact.prevent="sendMessage"
            />
            <button
              type="button"
              class="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-orange-400/20 bg-orange-400/10 text-orange-300 transition hover:bg-orange-400/20 disabled:opacity-40"
              :disabled="!newMessage.trim() || sending"
              @click="sendMessage"
            >
              <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
                <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.chat-pop-enter-active {
  transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}
.chat-pop-leave-active {
  transition: all 0.2s ease;
}
.chat-pop-enter-from {
  opacity: 0;
  transform: translateY(20px) scale(0.95);
}
.chat-pop-leave-to {
  opacity: 0;
  transform: translateY(10px) scale(0.97);
}
</style>
