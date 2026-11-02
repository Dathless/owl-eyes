export const defaultToolRenderer = {
  summary: (tool) =>
    `${tool.observations?.length ?? 0} observations, ${tool.evidence?.length ?? 0} evidence`,
};
export const toolRenderers = {};
