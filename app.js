const express = require("express");
const mysql = require("mysql");
const casbin = require("casbin");
const KnexAdapter = require("casbin-knex-adapter");
const knex = require("knex")({
  client: "mysql",
  connection: {
    host: "localhost",
    user: "root",
    password: "",
    database: "casbin_playground"
  }
});

const app = express();
const port = 5000;

app.set("port", port);

app.get("/", async (request, response) => {
  response.send(
    `
    <a href="/rbac_via_user">rbac user</a><br>
    <a href="/rbac">rbac</a><br>
    <a href="/abac">abac</a><br>
    `
  );
});

app.get("/abac", async (request, response) => {
  // This example uses ABAC to enforce ownership of the object
  // before allowing the user to read it
  const adapter = await KnexAdapter.newAdapter(knex);
  const enforcer = await casbin.newEnforcer("abac_model.conf", adapter);

  const subject = {
    name: "alice",
    id: "user123" // <----- this
  };
  const object = {
    name: "doohickey",
    user_id: "user123" // <----- must match this
  };

  if ((await enforcer.enforce(subject, object)) === true) {
    response.send(`${subject.name} is allowed to access ${object.name}`);
  } else {
    response.send(`${subject.name} is not allowed to access ${object.name}`);
  }
});

app.get("/rbac_via_user", async (request, response) => {
  // This example uses the user's role property as the key
  // This saves you from having to add the role to the user
  // via casbin (as seen in the /rbac example).
  const adapter = await KnexAdapter.newAdapter(knex);
  const enforcer = await casbin.newEnforcer("rbac_model.conf", adapter);

  // Create role admin with some permissions on 'jobs'
  await enforcer.addPolicy("admin", "jobs", "read");
  await enforcer.addPolicy("admin", "jobs", "write");
  await enforcer.addPolicy("admin", "jobs", "create");
  await enforcer.addPolicy("admin", "jobs", "delete");

  const subject = { name: "alice", role: "admin" };
  const object = "jobs";
  const action = "read";

  // Check that "admin" can "read" from "jobs"
  if (await enforcer.enforce(subject.role, object, action)) {
    // permit alice to read data1
    response.send(`${subject.name} is allowed to ${action} from ${object}`);
  } else {
    // deny the request, show an error
    response.send(`${subject.name} is not allowed to ${action} from ${object}`);
  }
});

app.get("/rbac", async (request, response) => {
  const adapter = await KnexAdapter.newAdapter(knex);
  const enforcer = await casbin.newEnforcer("rbac_model.conf", adapter);

  // Create role admin with some permissions on 'jobs'
  await enforcer.addPolicy("admin", "jobs", "read");
  await enforcer.addPolicy("admin", "jobs", "write");
  await enforcer.addPolicy("admin", "jobs", "create");
  await enforcer.addPolicy("admin", "jobs", "delete");

  // Add "alice" to the admin role we just created
  await enforcer.addRoleForUser("alice", "admin");

  const subject = "alice";
  const object = "jobs";
  const action = "read";

  // Check that "alice" can "read" from "jobs" with her "admin" role
  if (await enforcer.enforce(subject, object, action)) {
    // permit alice to read data1
    response.send(`${subject} is allowed to ${action} from ${object}`);
  } else {
    // deny the request, show an error
    response.send(`${subject} is not allowed to ${action} from ${object}`);
  }
});

app.listen(port, () => {
  console.log(`Ready on http://localhost:${port}`);
});
