const QIMEI = 'libqimei.so';
const TERSAFE = 'libtersafe.so';

function log(tag, msg) {
  console.log('[' + tag + '] ' + msg);
}

function readStr(p, max) {
  try {
    return p.readCString(max || 256);
  } catch (e) {
    return '<unreadable>';
  }
}

Java.perform(function () {
  try {
    const U = Java.use('com.tencent.qimei.uin.U');
    const specs = [
      ['z', 'android.content.Context'],
      ['z2', 'android.content.Context'],
      ['o', ''],
      ['u', ''],
      ['p', ''],
      ['m', 'int'],
      ['x', 'java.lang.String']
    ];
    specs.forEach(function (s) {
      const name = s[0];
      const orig = s[1] === '' ? U[name].overload() : U[name].overload(s[1]);
      orig.implementation = function () {
        const r = orig.apply(this, arguments);
        const a = Array.prototype.slice.call(arguments).map(function (x) {
          return String(x);
        });
        log('qimei.U.' + name, 'args=' + JSON.stringify(a) + ' ret=' + r);
        return r;
      };
    });
  } catch (e) {
    log('err', 'U hook ' + e);
  }

  try {
    const Qimei = Java.use('com.tencent.qimei.sdk.Qimei');
    const o16 = Qimei.getQimei16.overload();
    o16.implementation = function () {
      const r = o16.call(this);
      log('qimei.16', String(r));
      return r;
    };
    const o36 = Qimei.getQimei36.overload();
    o36.implementation = function () {
      const r = o36.call(this);
      log('qimei.36', String(r));
      return r;
    };
  } catch (e) {
    log('err', 'Qimei hook ' + e);
  }

  try {
    const Holder = Java.use('com.tdatamaster.tdm.device.DeviceInfoHolder');
    const setS = Holder.SetStringDeviceInfo.overload('java.lang.String', 'java.lang.String', 'int');
    setS.implementation = function (k, v, t) {
      log('tdm.set', k + ' = ' + v + ' t=' + t);
      return setS.call(this, k, v, t);
    };
    const getS = Holder.GetStringDeviceInfo.overload('java.lang.String');
    getS.implementation = function (k) {
      const r = getS.call(this, k);
      log('tdm.get', k + ' -> ' + r);
      return r;
    };
  } catch (e) {
    log('err', 'DeviceInfoHolder hook ' + e);
  }

  try {
    const Tss = Java.use('com.tencent.tp.TssSdk');
    const rep = Tss.getReportData.overload();
    rep.implementation = function () {
      const r = rep.call(this);
      log('ace.report', String(r));
      return r;
    };
    const io = Tss.ioctl.overload('java.lang.String');
    io.implementation = function (cmd) {
      const r = io.call(this, cmd);
      log('ace.ioctl', cmd + ' -> ' + r);
      return r;
    };
  } catch (e) {
    log('err', 'TssSdk hook ' + e);
  }
});

function hookNative() {
  const qbase = Module.findBaseAddress(QIMEI);
  if (qbase) {
    Interceptor.attach(qbase.add(0x2b9d4), {
      onEnter: function (args) {
        log('qimei.2b9d4', 'mode=' + args[3].toInt32() + ' mode2=' + args[4].toInt32());
      }
    });
    log('hook', 'libqimei ' + qbase + ' 0x2b9d4');
  }

  const tbase = Module.findBaseAddress(TERSAFE);
  if (tbase) {
    Interceptor.attach(tbase.add(0x2ccd20), {
      onEnter: function (args) {
        log('ace.2ccd20', 'buf=' + args[1] + ' size=' + args[2].toInt32());
      },
      onLeave: function (ret) {
        log('ace.2ccd20.out', ret.isNull() ? 'null' : readStr(ret));
      }
    });
    Interceptor.attach(tbase.add(0x2ccf54), {
      onEnter: function (args) {
        this.buf = args[1];
      },
      onLeave: function () {
        log('ace.2ccf54.out', readStr(this.buf));
      }
    });
    log('hook', 'libtersafe ' + tbase + ' fake token');
  }
}

setTimeout(hookNative, 1500);
