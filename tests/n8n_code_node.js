// Runs one n8n Code node ("Run Once for All Items" mode) outside n8n, for the tests.
// stdin: {"workflow": path, "node": name, "input": [json, ...],
//         "nodes": {name: json}, "raw_body": string}
// stdout: {"ok": <returned items>} or {"error": <message>}
// Stands in for n8n's $input, $('Node name') and this.helpers.getBinaryDataBuffer.
const fs = require('fs');

const request = JSON.parse(fs.readFileSync(0, 'utf8'));
const workflow = JSON.parse(fs.readFileSync(request.workflow, 'utf8'));
const node = workflow.nodes.find((n) => n.name === request.node);
if (!node || typeof node.parameters?.jsCode !== 'string') {
  throw new Error(`No Code node named ${request.node}`);
}

const items = (request.input ?? []).map((json) => ({ json }));
const $input = { first: () => items[0], all: () => items };
const $ = (name) => {
  if (!(name in (request.nodes ?? {}))) throw new Error(`Node output not provided: ${name}`);
  const item = { json: request.nodes[name] };
  return { first: () => item, all: () => [item] };
};
const context = {
  helpers: { getBinaryDataBuffer: async () => Buffer.from(request.raw_body ?? '', 'utf8') },
};

const AsyncFunction = (async () => {}).constructor;
new AsyncFunction('$input', '$', node.parameters.jsCode)
  .call(context, $input, $)
  .then(
    (result) => process.stdout.write(JSON.stringify({ ok: result })),
    (error) => process.stdout.write(JSON.stringify({ error: String(error?.message ?? error) })),
  );
