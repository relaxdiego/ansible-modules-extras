#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 Dimension Data
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   - Aimon Bustardo <aimon.bustardo@dimensiondata.com>
#   - Bert Diwa      <Lamberto.Diwa@dimensiondata.com>
#   - Jay Riddell    <Jay.Riddell@dimensiondata.com>
#   - Mark Maglana   <mark@maglana.com>

# Make coding more python3-ish
from __future__ import (absolute_import, division)
__metaclass__ = type

from ansible.module_utils.basic import \
    AnsibleModuleFSM, create_events, create_states
from ansible.module_utils.dimensiondata import \
    get_credentials, get_dd_regions, get_network_domain, is_uuid, \
    get_unallocated_public_ips

from libcloud.common.dimensiondata import DimensionDataAPIException
from libcloud.compute.providers import get_driver as get_cp_driver
from libcloud.compute.types import Provider as ComputeProvider
from libcloud.loadbalancer.base import Member, Algorithm
from libcloud.loadbalancer.providers import get_driver as get_lb_driver
from libcloud.loadbalancer.types import Provider as LBProvider
import libcloud.security

# States
S = create_states('creating',
                  'deleting',
                  'dispatching',
                  'doing_nothing',
                  'getting_lb',
                  'initializing')

# Events
E = create_events('created',
                  'exited',
                  'initialized',
                  'lb_found',
                  'lb_not_found',
                  'must_create',
                  'must_delete',
                  'must_do_nothing')


def main():
    transitions = {
        (S.initializing, E.initialized): (S.getting_lb, get_lb),

        (S.getting_lb, E.lb_found): (S.dispatching, dispatch),

        (S.dispatching, E.must_create): (S.creating, create_lb),
        (S.dispatching, E.must_delete): (S.deleting, delete_lb),
        (S.dispatching, E.must_do_nothing): (S.doing_nothing, do_nothing),
    }

    regions = get_dd_regions()

    protocols = ['any', 'tcp', 'udp', 'http', 'ftp', 'smtp']

    algorithms = ['ROUND_ROBIN',
                  'LEAST_CONNECTIONS',
                  'SHORTEST_RESPONSE',
                  'PERSISTENT_IP']

    AnsibleModuleFSM(
        state_machine=dict(
            starting_state=S.initializing,
            starting_action=initialize,
            exit_event=E.exited,
            transitions=transitions
        ),
        argument_spec=dict(
            region=dict(default='na', choices=regions),
            location=dict(required=True, type='str'),
            network_domain=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            port=dict(default=None, type='int'),
            protocol=dict(default='http', choices=protocols),
            algorithm=dict(default='ROUND_ROBIN', choices=algorithms),
            members=dict(default=None, type='list'),
            ensure=dict(default='present', choices=['present', 'absent']),
            verify_ssl_cert=dict(required=False, default=True, type='bool'),
            listener_ip_address=dict(required=False, default=None, type='str')
        ),
    )


# ===============
# ACTIONS/HELPERS
# ===============

def create_lb(mod, dargs):
    members = [Member(m['name'], m['ip'], m.get('port'))
               for m in mod.params['members']]

    lb_con = dargs['lb_con']
    compute_con = dargs['compute_con']
    net_domain = dargs['net_domain']
    ip_address = get_or_create_ip_address(mod, compute_con, lb_con, net_domain)

    try:
        balancer = lb_con.create_balancer(
            mod.params['name'],
            mod.params['port'],
            mod.params['protocol'],
            getattr(Algorithm, mod.params['algorithm']),
            members,
            ex_listener_ip_address=ip_address)

        balancer_d = {
            'id': balancer.id,
            'name': balancer.name,
            'state': int(balancer.state),
            'ip': balancer.ip,
            'port': int(balancer.port) if balancer.port else 'Any Port'
        }
        mod.exit_json(changed=True,
                      msg="Load balancer created.",
                      load_balancer=balancer_d)

    except DimensionDataAPIException as e:
        mod.fail_json(msg="Error while creating load balancer: %s" % e)


def delete_lb(mod, dargs):
    balancer = dargs['lb']
    lb_con = dargs['lb_con']

    try:
        pool_id = balancer.extra.get('pool_id')
        if pool_id:
            pool = lb_con.ex_get_pool(pool_id)

        res = lb_con.destroy_balancer(balancer)

        if pool:
            members = lb_con.ex_get_pool_members(pool_id)
            for member in members:
                lb_con.ex_destroy_pool_member(member, destroy_node=True)

            lb_con.ex_destroy_pool(pool)

        mod.exit_json(changed=True, msg="Load balancer deleted: %s" % res)
    except DimensionDataAPIException as e:
        mod.fail_json(msg="Error deleting load balancer: %s" % e)


def dispatch(mod, dargs):
    ensure = mod.params['ensure']
    balancer = dargs.get('lb', None)

    if ensure == 'present' and not balancer:
        event = E.must_create
    elif ensure == 'absent' and balancer:
        event = E.must_delete
    else:
        event = E.must_do_nothing

    return event, dargs


def do_nothing(mod, dargs):
    ensure = mod.params['ensure']
    balancer = dargs.get('lb', None)

    if balancer and ensure == 'present':
        mod.exit_json(changed=False,
                      msg="Load balancer already exists")
    elif not balancer and ensure == 'absent':
        mod.exit_json(changed=False,
                      msg="Load balancer does not exist")
    else:
        mod.fail_json(msg="Unexpected scenario: ensure=%s, balancer=%r" %
                          (ensure, balancer))


def get_lb(mod, dargs):
    """
    Retrieves the load balancer object and saves it to dargs['lb']. Sets
    dargs['lb'] to None if load balancer name or ID referred to
    mod.params['name'] is not found.
    """
    lb_con = dargs['lb_con']
    lb_id = mod.params['name']

    if is_uuid(lb_id):
        balancer = get_lb_by_id(mod, lb_con, lb_id)
    else:
        balancer = get_lb_by_name(mod, lb_con, lb_id)

    dargs['lb'] = balancer

    if balancer:
        event = E.lb_found
    else:
        event = E.lb_not_found

    return event, dargs


def get_lb_by_id(mod, lb_con, lb_id):
    try:
        return lb_con.get_balancer(lb_id)
    except DimensionDataAPIException as e:
        if e.code == 'RESOURCE_NOT_FOUND':
            return None
        else:
            mod.fail_json(msg="Unexpected error while retrieving load "
                          "balancer id %s: %s" % (lb_id, e.code))


def get_lb_by_name(mod, lb_con, lb_name):
    try:
        balancers = lb_con.list_balancers()
    except DimensionDataAPIException as e:
        msg = "Failed to list load balancers: %s" % e.message
        mod.fail_json(msg=msg)

    found_balancers = filter(lambda x: x.name == lb_name, balancers)

    if found_balancers:
        return found_balancers[0]
    else:
        return None


def get_or_create_ip_address(mod, lb_con, compute_con, net_domain):
    ip_address = str(mod.params['listener_ip_address']).strip()

    if not ip_address:
        res = get_unallocated_public_ips(mod, compute_con, lb_con,
                                         net_domain, True, 1)
        ip_address = res['addresses'][0]

    return ip_address


def initialize(mod, dargs):
    """
    Initialize the load balancer connection for use by the rest
    of this module. The connection object is saved to dargs['lb_con']
    """
    credentials = get_credentials()
    username = credentials["user_id"]
    password = credentials["key"]
    region = 'dd-%s' % mod.params['region']
    location = mod.params['location']
    network_domain = mod.params['network_domain']

    # Verify the API server's SSL certificate?
    libcloud.security.VERIFY_SSL_CERT = mod.params['verify_ssl_cert']

    # Connect to compute service
    compute_drv = get_cp_driver(ComputeProvider.DIMENSIONDATA)
    compute_con = compute_drv(username, password, region=region)

    # Get Network Domain Object
    net_domain = get_network_domain(compute_con, network_domain, location)

    if not net_domain:
        mod.fail_json(msg="Network domain could not be found.")

    # Connect to load balancer service
    lb_drv = get_lb_driver(LBProvider.DIMENSIONDATA)
    lb_con = lb_drv(username, password, region=region)

    lb_con.ex_set_current_network_domain(net_domain.id)

    dargs['lb_con'] = lb_con
    dargs['compute_con'] = compute_con
    dargs['net_domain'] = net_domain

    return E.initialized, dargs


if __name__ == '__main__':
    main()
