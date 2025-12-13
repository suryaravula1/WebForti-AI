db = db.getSiblingDB("webforti");

db.knowledge_documents.createIndex({ id: 1 }, { unique: true });
db.knowledge_documents.createIndex({ cve_id: 1 });
db.knowledge_documents.createIndex({ source: 1 });
db.knowledge_documents.createIndex({ embedding_model: 1 });
db.cve_corpus.createIndex({ cve_id: 1 }, { unique: true });
db.cve_corpus.createIndex({ curated_family: 1 });
db.cve_corpus.createIndex({ severity: 1 });
db.cve_corpus.createIndex({ source: 1 });
db.feedback_items.createIndex({ cve_id: 1 });
db.feedback_items.createIndex({ created_at: -1 });

db.knowledge_documents.updateOne(
  { id: "snort-http-content-template" },
  {
    $set: {
      id: "snort-http-content-template",
      title: "Snort HTTP content rule template",
      text: "Use alert tcp any any -> $HOME_NET $HTTP_PORTS with flow:to_server,established and content match on URI or body payload indicators.",
      source: "seed"
    }
  },
  { upsert: true }
);
