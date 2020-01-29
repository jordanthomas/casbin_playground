var express = require("express");
var router = express.Router();
const db = require("../config/database");
const knexAdapter = require("casbin-knex-adapter");
const casbin = require("casbin");
const authz = require("../utils/authz");

const organizations = ["organization123", "organization456"];
const users = ["user123", "user456"];

const setupSystemRoles = async () => {
  const adapter = await knexAdapter.newAdapter(db);
  const enforcer = await casbin.newEnforcer("rbac_model.conf", adapter);

  await enforcer.addPermissionForUser("customer", "workorder", "read");
  await enforcer.addPermissionForUser("customer", "job", "read");
  await enforcer.addPermissionForUser(
    "organization_manager",
    "workorder",
    "create"
  );
  await enforcer.addPermissionForUser(
    "organization_manager",
    "workorder",
    "update"
  );
  await enforcer.addPermissionForUser(
    "organization_manager",
    "workorder",
    "cancel"
  );

  // Define role inheritance, organization_manager inherits from customer
  await enforcer.addRoleForUser("organization_manager", "customer");
};

const createDummyUsers = async () => {
  const adapter = await knexAdapter.newAdapter(db);
  const enforcer = await casbin.newEnforcer("rbac_model.conf", adapter);

  const members = [
    { id: users[0], organization: organizations[0], role: "customer" },
    {
      id: users[0],
      organization: organizations[1],
      role: "organization_manager"
    },
    { id: users[1], organization: organizations[1], role: "customer" },
    {
      id: users[1],
      organization: organizations[0],
      role: "organization_manager"
    }
  ];

  // Assign roles to users
  for (let i = 0; i < members.length; i++) {
    await enforcer.addRoleForUser(
      `${members[i].organization}|${members[i].id}`,
      members[i].role
    );
  }
};

router.get("/", async (request, response, next) => {
  setupSystemRoles();
  createDummyUsers();

  response.render("index", {
    title: "RBAC w/ Tenants"
  });
});

router.get("/user_login", async (request, response, next) => {
  const authorizer = await authz.init();

  const userPermissions = [
    {
      user: users[0],
      organization: organizations[0],
      roles: await authorizer.getRolesForUser(organizations[0], users[0]),
      permissions: await authorizer.getPermissionsForUser(
        organizations[0],
        users[0]
      ),
      json: JSON.stringify(
        {
          permissions: await authorizer.getPermissionsForUser(
            organizations[0],
            users[0]
          )
        },
        null,
        2
      )
    },
    {
      user: users[0],
      organization: organizations[1],
      roles: await authorizer.getRolesForUser(organizations[1], users[0]),
      permissions: await authorizer.getPermissionsForUser(
        organizations[1],
        users[0]
      ),
      json: JSON.stringify(
        {
          permissions: await authorizer.getPermissionsForUser(
            organizations[1],
            users[0]
          )
        },
        null,
        2
      )
    },
    {
      user: users[1],
      organization: organizations[0],
      roles: await authorizer.getRolesForUser(organizations[0], users[1]),
      permissions: await authorizer.getPermissionsForUser(
        organizations[0],
        users[1]
      ),
      json: JSON.stringify(
        {
          permissions: await authorizer.getPermissionsForUser(
            organizations[0],
            users[1]
          )
        },
        null,
        2
      )
    },
    {
      user: users[1],
      organization: organizations[1],
      roles: await authorizer.getRolesForUser(organizations[1], users[1]),
      permissions: await authorizer.getPermissionsForUser(
        organizations[1],
        users[1]
      ),
      json: JSON.stringify(
        {
          permissions: await authorizer.getPermissionsForUser(
            organizations[1],
            users[1]
          )
        },
        null,
        2
      )
    }
  ];

  response.render("user_login", {
    userPermissions
  });
});

module.exports = router;
