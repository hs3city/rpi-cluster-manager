__version__ = "1.2.3"
import re
import json
import logging
import os
from datetime import datetime

from flask import (
    Flask,
    flash,
    render_template,
    redirect,
    url_for,
    request,
    jsonify,
    abort,
)
from flask_cors import CORS
from flask_login import (
    LoginManager,
    login_required,
    current_user,
    login_user,
    logout_user,
)

from whois import settings
from whois.database import db, Device, User
from whois.helpers import (
    owners_from_devices,
    filter_hidden,
    unclaimed_devices,
    filter_anon_names,
    ip_range,
    in_space_required,
)
from whois.mikrotik import parse_mikrotik_data
from matka import network_utils
from matka.host_control import get_hostnames, get_forwarded_ports, set_hostname, remove_hostname
from collections import namedtuple


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
login_manager = LoginManager()
login_manager.init_app(app)

cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

common_vars_tpl = {"version": __version__}

DevInfo = namedtuple('DevInfo', ['ip', 'mac_address', 'hostname', 'owner'])


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.get_by_id(user_id)
    except User.DoesNotExist as exc:
        app.logger.error("{}".format(exc))
        app.logger.error("return None")
        return None


@app.before_request
def before_request():
    app.logger.info("connecting to db")
    db.connect()

    if request.headers.getlist("X-Forwarded-For"):
        ip_addr = request.headers.getlist("X-Forwarded-For")[0]
        logger.info(
            "forward from %s to %s",
            request.remote_addr,
            request.headers.getlist("X-Forwarded-For")[0],
        )
    else:
        ip_addr = request.remote_addr

    if not ip_range(settings.ip_mask, ip_addr):
        app.logger.error("%s", request.headers)
        flash("Outside local network, some functions forbidden!", "outside-warning")


@app.teardown_appcontext
def after_request(error):
    app.logger.info("closing db")
    db.close()
    if error:
        app.logger.error(error)


@app.route("/")
def index():
    """Serve list of people in hs, show panel for logged users"""

    return render_template(
        "landing.html",
        **common_vars_tpl
    )


class _Device:
    def __init__(self, network_scan_result):
        self.mac_address = network_scan_result.mac
        self.hostname = "-"
        self.owner = "-"
        self.ip = network_scan_result.ip

from hashlib import sha1
import json


def calculate_db_hash(dhcp_config, firewall_config):
    hash = sha1(json.dumps([dhcp_config, firewall_config], sort_keys=True).encode())
    return hash.hexdigest()


def find_host_in_dhcp_cfg(cfg, mac):
    try:
        return next(filter(lambda section: section.get('mac', '') == mac, cfg))
    except:
        return ''


# TODO change/remove
@login_required
@app.route("/devices")
def devices():
    scan_result = network_utils.scan_network(interface=settings.lab_net_interface)

    firewall_config = get_forwarded_ports(settings.router_login_info)
    dhcp_config = get_hostnames(settings.router_login_info)
    db_hash = calculate_db_hash(dhcp_config, firewall_config)

    unclaimed_devices = []
    devices_in_network = []
    mine = []

    for dev in scan_result:
        devices_in_network.append(DevInfo(dev.ip, dev.mac.upper(), find_host_in_dhcp_cfg(dhcp_config, dev.mac), None))
    
    for processed_dev in devices_in_network:
        claimed = False
        for claimed_device in Device.select():
            if claimed_device.mac_address == processed_dev.mac_address:
                claimed = True
                if getattr(processed_dev.owner,'get_id', lambda : None)() == current_user.get_id():
                    mine.append(processed_dev)
                    break
        if not claimed:
            unclaimed_devices.append(processed_dev)


    mine = current_user.devices
    return render_template(
        "devices.html",
        unclaimed=unclaimed_devices,
        my_devices=mine,
        db_state_hash=db_hash,
        **common_vars_tpl
    )

# TODO change
@app.route("/device/<mac_address>", methods=["GET", "POST"])
@login_required
@in_space_required()
def device_view(mac_address):
    """Get info about device, claim device, release device"""
    mac_address = mac_address.upper()
    hostname = request.values.get('hostname','').lower()
    if hostname:
        if re.search(r"[^a-z0-9_]+", hostname):
            flash('hostname contains not allowed chars')
            return redirect('/devices')
        hostname = "{}.lab.hs3.pl".format(hostname)

    firewall_config = get_forwarded_ports(settings.router_login_info)
    dhcp_config = get_hostnames(settings.router_login_info)
    db_hash = calculate_db_hash(dhcp_config, firewall_config)
    devices = network_utils.scan_network(settings.lab_net_interface)

    if request.method == "POST" and request.values.get("action") == "claim":
        if not hostname:
            flash("hostname is either empty ")
            return redirect('/devices')

        if db_hash != request.values.get('db_state_hash'):
            flash("Somethong has changed database state in the mean time, please try again."
                  "Wrong db hash. Got {} , expectd {}".format(request.values.get('db_state_hash'), db_hash))
            return redirect('/devices')
        try:
            device_status = next(filter(lambda dev: dev.mac.upper() == mac_address, devices))
        except:
            return abort(404)
        set_hostname(settings.router_login_info, device_status.ip, device_status.mac,
                     hostname)

        device = Device.create(mac_address=mac_address)
        device.owner = current_user.get_id()
        device.save()
    elif request.method == "POST" and request.values.get('action') == 'change_hostname':
        if db_hash != request.values.get('db_state_hash'):
            flash("Somethong has changed database state in the mean time, please try again."
                  "Wrong db hash. Got {} , expectd {}".format(request.values.get('db_state_hash'), db_hash))
            return redirect('/devices')
        device = current_user.devices.select().where(Device.mac_address == mac_address).execute()[0]
        device_status = next(filter(lambda dev: dev.mac.upper() == mac_address, devices))
        set_hostname(settings.router_login_info, device_status.ip, device_status.mac,
                    hostname)

        device = DevInfo(device_status.ip, device_status.mac, hostname, current_user)
    elif request.method == "POST" and request.values.get('action') == 'unclaim':
        device = current_user.devices.select().where(Device.mac_address == mac_address).execute()[0]
        device.delete_instance()
        hostname_cfg = next(filter(lambda hcfg: hcfg.get('mac', '').upper() == mac_address, dhcp_config))
        remove_hostname(settings.router_login_info, hostname_cfg['name'])
        flash("Host has been successfully unclaimed")
        return redirect('/devices')
    else:
        device_status = next(filter(lambda dev: dev.mac.upper() == mac_address, devices))
        device = Device.select().where(Device.mac_address == mac_address.upper()).execute()[0]
        device = DevInfo(device_status.ip, device_status.mac, hostname, current_user)

    return render_template("device.html", device=device, **common_vars_tpl,
           db_state_hash=db_hash)

# TODO change
@app.route("/register", methods=["GET", "POST"])
@in_space_required()
def register():
    """Registration form"""
    if current_user.is_authenticated:
        app.logger.error("Shouldn't register when auth")
        flash("Shouldn't register when auth", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        # TODO: WTF forms for safety
        display_name = request.form["display_name"]
        username = request.form["username"]
        password = request.form["password"]

        try:
            user = User.register(username, password, display_name)
        except Exception as exc:
            if exc.args[0] == "too_short":
                flash("Password too short, minimum length is 3")
            else:
                print(exc)
        else:
            user.save()
            app.logger.info("registered new user: {}".format(user.username))
            flash("Registered.", "info")

        return redirect(url_for("login"))

    return render_template("register.html", **common_vars_tpl)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login using naive db or LDAP (work on it @priest)"""
    if current_user.is_authenticated:
        app.logger.error("Shouldn't login when auth")
        flash("Shouldn't login when auth", "error")
        return redirect(url_for("devices"))

    if request.method == "POST":
        try:
            user = User.get(User.username == request.form["username"])
        except User.DoesNotExist:
            user = None

        if user is not None and user.auth(request.form["password"]) is True:
            login_user(user)
            app.logger.info("logged in: {}".format(user.username))
            flash(
                "Hello {}! You can now claim and manage your devices.".format(
                    current_user.username
                ),
                "success",
            )
            return redirect(url_for("devices"))
        else:
            app.logger.info("failed log in: {}".format(request.form["username"]))
            flash("Invalid credentials", "error")

    return render_template("login.html", **common_vars_tpl)


@app.route("/logout")
@login_required
def logout():
    username = current_user.username
    logout_user()
    app.logger.info("logged out: {}".format(username))
    flash("Logged out.", "info")
    return redirect(url_for("index"))

# TODO change
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile_edit():
    # TODO: logging
    if request.method == "POST":
        if current_user.auth(request.values.get("password", None)) is True:
            try:
                if (
                    request.form["new_password"] is not None
                    and len(request.form["new_password"]) > 0
                ):
                    current_user.password = request.form["new_password"]
            except Exception as exc:
                if exc.args[0] == "too_short":
                    flash("Password too short, minimum length is 3", "warning")
                else:
                    app.logger.error(exc)
            else:
                current_user.display_name = request.form["display_name"]
                new_flags = request.form.getlist("flags")
                current_user.is_hidden = "hidden" in new_flags
                current_user.is_name_anonymous = "anonymous for public" in new_flags
                app.logger.info(
                    "flags: got {} set {:b}".format(new_flags, current_user.flags)
                )
                current_user.save()
                flash("Saved", "success")
        else:
            flash("Invalid password", "error")

    return render_template("profile.html", user=current_user, **common_vars_tpl)
