const db = require("../config/database");
const casbin = require("casbin");
const knexAdapter = require("casbin-knex-adapter");

class Authorizer {
  constructor(enforcer) {
    if (!enforcer) throw new Error("An enforcer is required");
    this.enforcer = enforcer;
  }

  static async init() {
    const adapter = await knexAdapter.newAdapter(db);
    const enforcer = await casbin.newEnforcer("rbac_model.conf", adapter);
    return new Authorizer(enforcer);
  }

  createKey(organizationId, userId) {
    return `${organizationId}|${userId}`;
  }

  async getRolesForUser(organizationId, userId) {
    const key = this.createKey(organizationId, userId);

    return await this.enforcer.getRolesForUser(key);
  }

  async getPermissionsForUser(organizationId, userId) {
    const key = this.createKey(organizationId, userId);
    const permissions = await this.enforcer.getImplicitPermissionsForUser(key);

    // Convert policies to camelcased permissions.
    // ['admin', 'widget', 'read'] => widgetRead
    return permissions.map(permission => {
      const [_role, object, action] = permission;

      return `${object}${action.charAt(0).toUpperCase()}${action.slice(1)}`;
    });
  }

  async addRole(organizationId, userId, role) {
    const key = this.createKey(organizationId, userId);

    return this.enforcer.addRoleForUser(key, role);
  }

  async deleteRole(organizationId, userId, role) {
    const key = this.createKey(organizationId, userId);

    // Delete is broken in casbin-knex-adapter
    // https://github.com/sarneeh/casbin-knex-adapter/pull/2
    return this.enforcer.deleteRoleForUser(key, role);
  }
}

module.exports = Authorizer;
