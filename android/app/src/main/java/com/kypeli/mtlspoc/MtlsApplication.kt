package com.kypeli.mtlspoc

import android.app.Application
import com.kypeli.mtlspoc.di.AppGraph
import dev.zacsweers.metro.createGraphFactory

class MtlsApplication : Application() {
    val appGraph: AppGraph by lazy {
        createGraphFactory<AppGraph.Factory>().create(this)
    }
}
