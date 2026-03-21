<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";

const props = defineProps<{
  modelValue: string;
  label: string;
  placeholder?: string;
}>();

const emit = defineEmits<{
  "update:modelValue": [value: string];
}>();

const MONTH_NAMES = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
];

const WEEKDAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

const rootElement = ref<HTMLElement | null>(null);
const isOpen = ref(false);

function parseDateString(value: string) {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return null;
  }

  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(year, month - 1, day);
  if (
    Number.isNaN(date.getTime()) ||
    date.getFullYear() !== year ||
    date.getMonth() !== month - 1 ||
    date.getDate() !== day
  ) {
    return null;
  }

  return date;
}

function formatDateValue(date: Date) {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function formatDisplayDate(value: string) {
  const date = parseDateString(value);
  if (!date) {
    return props.placeholder ?? "Select date";
  }

  const pad = (item: number) => String(item).padStart(2, "0");
  return `${pad(date.getDate())}-${pad(date.getMonth() + 1)}-${date.getFullYear()}`;
}

const selectedDate = computed(() => parseDateString(props.modelValue));
const displayedMonth = ref(selectedDate.value ? new Date(selectedDate.value) : new Date());

watch(
  () => props.modelValue,
  (value) => {
    const parsed = parseDateString(value);
    if (parsed) {
      displayedMonth.value = new Date(parsed);
    }
  },
);

const monthLabel = computed(() => `${MONTH_NAMES[displayedMonth.value.getMonth()]} ${displayedMonth.value.getFullYear()}`);

const calendarDays = computed(() => {
  const year = displayedMonth.value.getFullYear();
  const month = displayedMonth.value.getMonth();
  const firstDay = new Date(year, month, 1);
  const startOffset = (firstDay.getDay() + 6) % 7;
  const startDate = new Date(year, month, 1 - startOffset);

  return Array.from({ length: 42 }, (_, index) => {
    const date = new Date(startDate);
    date.setDate(startDate.getDate() + index);
    const value = formatDateValue(date);
    return {
      value,
      day: date.getDate(),
      isCurrentMonth: date.getMonth() === month,
      isSelected: value === props.modelValue,
      isToday: value === formatDateValue(new Date()),
    };
  });
});

function previousMonth() {
  displayedMonth.value = new Date(displayedMonth.value.getFullYear(), displayedMonth.value.getMonth() - 1, 1);
}

function nextMonth() {
  displayedMonth.value = new Date(displayedMonth.value.getFullYear(), displayedMonth.value.getMonth() + 1, 1);
}

function selectDate(value: string) {
  emit("update:modelValue", value);
  isOpen.value = false;
}

function clearDate() {
  emit("update:modelValue", "");
  isOpen.value = false;
}

function toggleCalendar() {
  isOpen.value = !isOpen.value;
}

function closeCalendar() {
  isOpen.value = false;
}

function handlePointerDown(event: MouseEvent) {
  if (!rootElement.value) {
    return;
  }

  const target = event.target as Node | null;
  if (target && !rootElement.value.contains(target)) {
    closeCalendar();
  }
}

onMounted(() => {
  document.addEventListener("mousedown", handlePointerDown);
});

onBeforeUnmount(() => {
  document.removeEventListener("mousedown", handlePointerDown);
});
</script>

<template>
  <div ref="rootElement" class="relative">
    <button
      type="button"
      class="group block w-full rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2.5 text-left transition hover:border-orange-400/25"
      @click="toggleCalendar"
    >
      <span class="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">{{ label }}</span>
      <span class="mt-1 block text-sm font-medium normal-case text-white">
        {{ formatDisplayDate(modelValue) }}
      </span>
    </button>

    <div
      v-if="isOpen"
      class="absolute left-0 top-[calc(100%+0.6rem)] z-50 w-[19rem] rounded-[1rem] border border-white/10 bg-slate-950/98 p-3 shadow-2xl shadow-black/40 backdrop-blur-xl"
    >
      <div class="flex items-center justify-between gap-2">
        <button
          type="button"
          class="flex h-9 w-9 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
          @click="previousMonth"
        >
          ‹
        </button>
        <p class="text-sm font-semibold text-white">{{ monthLabel }}</p>
        <button
          type="button"
          class="flex h-9 w-9 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
          @click="nextMonth"
        >
          ›
        </button>
      </div>

      <div class="mt-3 grid grid-cols-7 gap-1 text-center text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">
        <span v-for="weekday in WEEKDAY_NAMES" :key="weekday">{{ weekday }}</span>
      </div>

      <div class="mt-2 grid grid-cols-7 gap-1">
        <button
          v-for="day in calendarDays"
          :key="day.value"
          type="button"
          class="flex h-10 items-center justify-center rounded-xl text-sm font-medium transition"
          :class="[
            day.isSelected
              ? 'bg-orange-400/18 text-orange-100 ring-1 ring-orange-400/35'
              : day.isCurrentMonth
                ? 'text-slate-200 hover:bg-white/[0.06]'
                : 'text-slate-600 hover:bg-white/[0.03]',
            day.isToday && !day.isSelected ? 'border border-sky-400/20 bg-sky-400/8' : '',
          ]"
          @click="selectDate(day.value)"
        >
          {{ day.day }}
        </button>
      </div>

      <div class="mt-3 flex items-center justify-between gap-2">
        <button
          type="button"
          class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
          @click="clearDate"
        >
          Clear
        </button>
        <button
          type="button"
          class="rounded-full border border-orange-400/20 bg-orange-400/10 px-3 py-1.5 text-xs font-semibold text-orange-100 transition hover:border-orange-400/35 hover:bg-orange-400/18"
          @click="closeCalendar"
        >
          Done
        </button>
      </div>
    </div>
  </div>
</template>
