<template>
  <span 
    class="ip-address" 
    @contextmenu.prevent="showMenu"
    title="右键点击以添加到IP集"
  >
    {{ ip }}
  </span>
</template>

<script setup>
const props = defineProps({
  ip: {
    type: String,
    required: true
  }
});

const emit = defineEmits(['show-menu']);

const showMenu = (event) => {
  emit('show-menu', {
    ip: props.ip,
    x: event.clientX,
    y: event.clientY,
  });
};
</script>

<style scoped>
.ip-address {
  cursor: pointer;
  text-decoration: underline;
  text-decoration-style: dotted;
  text-underline-offset: 2px;
}
.ip-address:hover {
  background-color: rgba(0, 123, 255, 0.1);
}
</style>